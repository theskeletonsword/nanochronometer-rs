// SPDX-License-Identifier: Apache-2.0
//! The pool: every source in, XDRBG-256 out. See the module docs in
//! [`super`] for the crediting rules.

use super::health::{self, OSR_MAX};
use super::hwrng::{HwRng, HwState};
use super::jitter::{self, Jitter, Sampler, StartupReport};
use super::keccak::{self, wipe_bytes, Sponge, DOMAIN_SHA3, DOMAIN_SHAKE, RATE};
use super::stream::{self, Engine, EngineChoice, Stream, CHUNK};
use super::xdrbg::{self, Xdrbg, BLOCK_LEN, STATE_LEN};
use super::{
    Mode, RngError, Status, FLAG_DEGRADED, FLAG_ENGINE_FALLBACK, FLAG_FAILED, FLAG_READY,
    FLAG_SELFTEST_PASSED, SOURCE_EVENTS, SOURCE_EXTERNAL, SOURCE_JITTER, SOURCE_PMU,
    SOURCE_RDRAND, SOURCE_RDSEED,
};

// Domain bytes of the blocks that are not jitter samples (which use
// `jitter::DOMAIN_JITTER`, 0x01), so no two sources' blocks can collide.
const DOMAIN_RDSEED: u8 = 0x02;
const DOMAIN_RDRAND: u8 = 0x03;
const DOMAIN_EXTERNAL: u8 = 0x04;
const DOMAIN_EVENTS: u8 = 0x05;

/// Credited bits a seed must carry: the 256-bit security level…
const SEED_BITS: u32 = 256;
/// …plus the manual's compliance margin `F`.
const COMPLIANCE_MARGIN: u32 = 65;
/// Hardware words mixed in, uncredited, alongside a jitter seed.
const HW_EXTRA_WORDS: u32 = 4;
/// Bytes read from the embedder's source per seed.
const EXTERNAL_BYTES: usize = 64;
/// Additional input binding an output-stage key to its purpose.
const STREAM_KEY_LABEL: &[u8] = b"NC_RNG output stage key";
/// Additional input marking an event fold (see `fold_events`).
const EVENTS_LABEL: &[u8] = b"NC_RNG events";
/// Stirred events that trigger a fold into the generator on the next fast
/// read: a burst of typing or a USB transfer reaches the output within one
/// request, not after the next megabyte.
const EVENT_FOLD: u64 = 64;

/// How the pool is set up. [`Config::DEFAULT`] is the manual's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Oversampling rate, 1..=20: jitter samples per credited bit. 0 picks 3.
    pub osr: u32,
    /// Memory accesses per jitter measurement.
    pub mem_steps: u32,
    /// Hash-loop iterations per jitter measurement.
    pub hash_loops: u32,
    /// Add the compliance margin (65 bits) to every seed.
    pub compliance: bool,
    /// [`Mode::Fast`] output between reseeds, in bytes.
    pub reseed_interval: u64,
    /// Refuse to seed from hardware or the embedder when the timer fails.
    pub require_jitter: bool,
    /// The output stage's engine: the best the CPU has, or ChaCha20.
    pub engine: EngineChoice,
}

impl Config {
    pub const DEFAULT: Config = Config {
        osr: health::OSR_DEFAULT,
        mem_steps: jitter::DEFAULT_MEM_STEPS,
        hash_loops: jitter::DEFAULT_HASH_LOOPS,
        compliance: true,
        reseed_interval: 1 << 20,
        require_jitter: false,
        engine: EngineChoice::Auto,
    };

    /// Credited bits per seed.
    pub const fn seed_bits(&self) -> u32 {
        SEED_BITS + if self.compliance { COMPLIANCE_MARGIN } else { 0 }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A source the embedder supplies: the OS's CSPRNG on a hosted build, a
/// board TRNG in a kernel that has one.
#[derive(Debug, Clone, Copy)]
pub struct External {
    /// Fills the buffer; `false` if it could not.
    pub read: fn(&mut [u8]) -> bool,
    /// Entropy per output bit the embedder vouches for, in eighths of a bit
    /// (8 = full entropy). Counted only when the jitter source cannot run.
    pub credit_eighths: u32,
}

// `repr(u8)` on both state enums: an explicit tag instead of a niche in
// `RngError`'s negative discriminants, which GDB misreads (every dataless
// variant printed as `Failed(-13)`). The kernel is debugged under GDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PoolState {
    /// Constructed; nothing measured yet.
    Cold,
    Ready,
    /// Out of service. Every read returns this.
    Failed(RngError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum JitterState {
    Untested,
    Ready,
    Failed(RngError),
}

/// The pool. See the module docs.
pub struct EntropyPool<'r> {
    config: Config,
    jitter: Jitter<'r>,
    jitter_state: JitterState,
    startup: StartupReport,
    hw: HwRng,
    external: Option<External>,
    drbg: Xdrbg,
    /// The output stage, keyed from `drbg` at every seed.
    stream: Stream,
    /// The CPU's AES path failed its known answers and ChaCha20 replaced it.
    engine_fallback: bool,
    /// Stirred events since the last seed, absorbed as they come.
    events: Sponge,
    events_total: u64,
    events_pending: u64,
    state: PoolState,
    selftest_passed: bool,
    health_latched: u32,
    last_error: Option<RngError>,
    last_sources: u32,
    reseeds: u64,
    bytes_out: u64,
    since_reseed: u64,
}

impl core::fmt::Debug for EntropyPool<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntropyPool")
            .field("state", &self.state)
            .field("jitter", &self.jitter)
            .field("reseeds", &self.reseeds)
            .finish_non_exhaustive()
    }
}

impl<'r> EntropyPool<'r> {
    /// A pool over `region` (a power of two, 1 KiB to 512 MiB; the manual's
    /// default is [`jitter::DEFAULT_REGION_LEN`]). Measures nothing: the
    /// first read, or [`start`](Self::start), does that.
    pub fn new(region: &'r mut [u8], config: Config) -> Result<Self, RngError> {
        let jitter = Jitter::new(region, config.osr, config.mem_steps, config.hash_loops)?;
        Ok(EntropyPool {
            config,
            jitter,
            jitter_state: JitterState::Untested,
            startup: StartupReport::default(),
            hw: HwRng::absent(),
            external: None,
            drbg: Xdrbg::new(),
            stream: Stream::new(),
            engine_fallback: false,
            events: Sponge::new(),
            events_total: 0,
            events_pending: 0,
            state: PoolState::Cold,
            selftest_passed: false,
            health_latched: 0,
            last_error: None,
            last_sources: 0,
            reseeds: 0,
            bytes_out: 0,
            since_reseed: 0,
        })
    }

    /// A counter read around every jitter measurement (a PMU event).
    pub fn set_sampler(&mut self, sampler: Option<Sampler>) {
        self.jitter.set_sampler(sampler);
    }

    /// The embedder's own source, if it has one.
    pub fn set_external(&mut self, external: Option<External>) {
        self.external = external;
    }

    pub fn is_ready(&self) -> bool {
        self.state == PoolState::Ready
    }

    /// Known-answer tests, source detection, jitter start-up and the first
    /// seed. Called by the first read if not before; calling it at boot
    /// moves the ~2000 measurements it takes off the first reader's path.
    pub fn start(&mut self) -> Result<(), RngError> {
        match self.state {
            PoolState::Failed(error) => return Err(error),
            PoolState::Ready => return Ok(()),
            PoolState::Cold => {}
        }
        self.selftest()?;
        self.hw = HwRng::detect();
        // A timer that fails start-up is not fatal here: the seed below may
        // still come from another credited source, flagged degraded.
        let _ = self.start_jitter();
        if let Err(error) = self.reseed() {
            return Err(self.record(error));
        }
        self.state = PoolState::Ready;
        Ok(())
    }

    /// Re-runs the known-answer tests (the manual's periodic self-test) and
    /// settles the output stage's engine. A failure of the sponge, the XDRBG
    /// or ChaCha20 takes the pool out of service; a hardware AES path that
    /// fails is replaced by ChaCha20 and flagged.
    pub fn selftest(&mut self) -> Result<(), RngError> {
        if !(keccak::selftest() && xdrbg::selftest() && stream::selftest(Engine::ChaCha20)) {
            self.selftest_passed = false;
            return Err(self.record(RngError::SelfTest));
        }
        let wanted = match self.config.engine {
            EngineChoice::Auto => Engine::detect(),
            EngineChoice::Software => Engine::ChaCha20,
        };
        let engine = if wanted == Engine::ChaCha20 || stream::selftest(wanted) {
            wanted
        } else {
            self.engine_fallback = true;
            Engine::ChaCha20
        };
        self.stream.set_engine(engine);
        self.selftest_passed = true;
        Ok(())
    }

    /// The output stage's engine.
    pub fn engine(&self) -> Engine {
        self.stream.engine()
    }

    /// Fills `out`, or returns an error and leaves `out` zeroed: never a
    /// partial buffer.
    pub fn fill(&mut self, out: &mut [u8], mode: Mode) -> Result<usize, RngError> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Err(error) = self.start() {
            wipe_bytes(out);
            return Err(error);
        }
        let mut done = 0;
        while done < out.len() {
            if mode == Mode::True
                || !self.drbg.is_seeded()
                || self.since_reseed >= self.config.reseed_interval
            {
                if let Err(error) = self.reseed() {
                    wipe_bytes(out);
                    return Err(self.record(error));
                }
            }
            let n = match mode {
                // Straight from the freshly seeded XDRBG, a block at a time.
                Mode::True => {
                    let n = (out.len() - done).min(BLOCK_LEN);
                    self.drbg.generate(&mut out[done..done + n], &[]);
                    n
                }
                // The output stage: one nonce and one key per chunk.
                Mode::Fast => {
                    if self.events_pending >= EVENT_FOLD {
                        self.fold_events();
                    }
                    let n = (out.len() - done).min(CHUNK);
                    if let Err(error) = self.stream.generate(&mut out[done..done + n]) {
                        wipe_bytes(out);
                        return Err(self.record(error));
                    }
                    n
                }
            };
            done += n;
            self.since_reseed += n as u64;
        }
        self.bytes_out += done as u64;
        Ok(done)
    }

    /// Mixes in an event: a caller-chosen tag, a value, and the counter at
    /// the moment of the call — which is what carries the entropy, since
    /// when a key is pressed or a transfer completes is not predictable to
    /// the cycle. Never credited. Cheap: a permutation every few calls.
    pub fn stir(&mut self, tag: u64, value: u64) {
        let now = crate::arch::counter_raw();
        let mut record = [0u8; 24];
        record[..8].copy_from_slice(&tag.to_le_bytes());
        record[8..16].copy_from_slice(&value.to_le_bytes());
        record[16..].copy_from_slice(&now.to_le_bytes());
        self.events.absorb(&record);
        self.events_total += 1;
        self.events_pending += 1;
    }

    /// A snapshot for the status call.
    pub fn status(&self) -> Status {
        let mut flags = 0;
        if self.state == PoolState::Ready && self.drbg.is_seeded() {
            flags |= FLAG_READY;
            if self.last_sources & SOURCE_JITTER == 0 {
                flags |= FLAG_DEGRADED;
            }
        }
        if matches!(self.state, PoolState::Failed(_)) {
            flags |= FLAG_FAILED;
        }
        if self.selftest_passed {
            flags |= FLAG_SELFTEST_PASSED;
        }
        if self.engine_fallback {
            flags |= FLAG_ENGINE_FALLBACK;
        }

        let mut available = SOURCE_EVENTS;
        if self.jitter_state == JitterState::Ready {
            available |= SOURCE_JITTER;
        }
        if self.hw.rdseed_state() == HwState::Healthy {
            available |= SOURCE_RDSEED;
        }
        if self.hw.rdrand_state() == HwState::Healthy {
            available |= SOURCE_RDRAND;
        }
        if self.jitter.has_sampler() {
            available |= SOURCE_PMU;
        }
        if self.external.is_some() {
            available |= SOURCE_EXTERNAL;
        }

        Status {
            size: core::mem::size_of::<Status>() as u32,
            flags,
            sources: self.last_sources,
            available,
            health: self.health_latched,
            last_error: self.last_error.map_or(0, RngError::code),
            osr: self.jitter.osr(),
            startup_stuck_permille: self.startup.stuck * 1000 / jitter::STARTUP_SAMPLES,
            engine: if self.selftest_passed { self.stream.engine() as u32 } else { 0 },
            reserved: 0,
            granularity: self.jitter.granularity(),
            reseeds: self.reseeds,
            bytes_out: self.bytes_out,
            jitter_samples: self.jitter.samples(),
            jitter_stuck: self.jitter.stuck(),
            events: self.events_total,
            hw_words: self.hw.words,
            nonces: self.stream.nonces_used(),
        }
    }

    /// Erases the generator and the pending events; the next read starts
    /// over from the self-tests. The manual's release step.
    pub fn wipe(&mut self) {
        self.drbg.wipe();
        self.stream.wipe();
        self.events.wipe();
        self.events_pending = 0;
        if self.state == PoolState::Ready {
            self.state = PoolState::Cold;
        }
    }

    /// Folds the stirred events into the generator as additional input and
    /// rekeys the output stage. Not a reseed — nothing is credited, and the
    /// credited schedule is unchanged — but every key press and USB
    /// completion since the last fold reaches the output from the next
    /// request on. Mixing can only add to what an attacker must guess.
    fn fold_events(&mut self) {
        let mut digest = [0u8; 32];
        self.events.finish(DOMAIN_SHA3);
        self.events.squeeze(&mut digest);
        self.events.wipe();
        self.events_pending = 0;
        self.drbg.reseed(&digest, EVENTS_LABEL);
        wipe_bytes(&mut digest);
        let mut key = [0u8; 32];
        self.drbg.generate(&mut key, STREAM_KEY_LABEL);
        self.stream.rekey(&key);
        wipe_bytes(&mut key);
    }

    /// Notes an error, and takes the pool out of service if it is one the
    /// manual treats as permanent. Returns it, for `?`-style chaining.
    fn record(&mut self, error: RngError) -> RngError {
        self.last_error = Some(error);
        if matches!(
            error,
            RngError::SelfTest
                | RngError::RctPermanent
                | RngError::AptPermanent
                | RngError::LagPermanent
                | RngError::MemoryPermanent
        ) || (self.config.require_jitter && error == RngError::Timer)
        {
            self.drbg.wipe();
            self.stream.wipe();
            self.state = PoolState::Failed(error);
        }
        error
    }

    fn latch(&mut self, error: RngError) {
        self.last_error = Some(error);
        self.health_latched |= match error {
            RngError::Rct => health::FAIL_RCT,
            RngError::Apt => health::FAIL_APT,
            RngError::Lag => health::FAIL_LAG,
            RngError::RctPermanent => health::FAIL_RCT_PERMANENT,
            RngError::AptPermanent => health::FAIL_APT_PERMANENT,
            RngError::LagPermanent => health::FAIL_LAG_PERMANENT,
            _ => 0,
        };
    }

    fn start_jitter(&mut self) -> Result<(), RngError> {
        match self.jitter.startup() {
            Ok(report) => {
                self.startup = report;
                self.jitter_state = JitterState::Ready;
                Ok(())
            }
            Err(error) => {
                self.latch(error);
                self.jitter_state = JitterState::Failed(error);
                Err(error)
            }
        }
    }

    /// Collects a credited jitter seed, applying the resilient rule: an
    /// intermittent failure discards the block, raises the OSR and
    /// re-validates the timer; past OSR 20 the failure is permanent.
    fn collect_jitter(&mut self, seed: &mut Sponge, bits: u32) -> Result<(), RngError> {
        loop {
            match self.jitter.collect(seed, bits) {
                Ok(_) => return Ok(()),
                Err(error) => {
                    self.latch(error);
                    if !error.is_intermittent() {
                        return Err(error);
                    }
                    let osr = self.jitter.osr() + 1;
                    if osr > OSR_MAX {
                        let permanent = error.escalate();
                        self.latch(permanent);
                        return Err(permanent);
                    }
                    seed.wipe();
                    self.jitter.retune(osr);
                    self.start_jitter()?;
                }
            }
        }
    }

    /// Gathers every source into a fresh sponge and (re)seeds the XDRBG from
    /// it — or fails, discarding everything, if fewer than the configured
    /// bits could be credited.
    fn reseed(&mut self) -> Result<(), RngError> {
        let need = self.config.seed_bits();
        let mut seed = Sponge::new();
        let mut credited = 0u32;
        let mut sources = 0u32;

        // 1. Timing jitter: the credited, health-tested primary.
        if self.jitter_state == JitterState::Ready {
            match self.collect_jitter(&mut seed, need) {
                Ok(()) => {
                    credited = need;
                    sources |= SOURCE_JITTER;
                    if self.jitter.has_sampler() {
                        sources |= SOURCE_PMU;
                    }
                }
                Err(error) => {
                    // Half a seed of a source that just failed is not kept.
                    seed.wipe();
                    self.jitter_state = JitterState::Failed(error);
                }
            }
        }
        if self.config.require_jitter && credited < need {
            seed.wipe();
            return Err(self.jitter_error());
        }

        let mut block = [0u8; RATE];

        // 2. RDSEED. Credited at half its width only if the jitter source
        //    could not credit this seed; otherwise a few words ride along.
        let short = credited < need;
        let words = if short { (2 * need).div_ceil(64) } else { HW_EXTRA_WORDS };
        for _ in 0..words {
            let Some(word) = self.hw.rdseed() else { break };
            absorb_word(&mut seed, &mut block, DOMAIN_RDSEED, word);
            sources |= SOURCE_RDSEED;
            if short {
                credited += 32;
            }
        }

        // 3. RDRAND: a DRBG's output; mixed, never credited.
        for _ in 0..HW_EXTRA_WORDS {
            let Some(word) = self.hw.rdrand() else { break };
            absorb_word(&mut seed, &mut block, DOMAIN_RDRAND, word);
            sources |= SOURCE_RDRAND;
        }

        // 4. The embedder's source, credited only if still short.
        if let Some(external) = self.external {
            let mut bytes = [0u8; EXTERNAL_BYTES];
            if (external.read)(&mut bytes) {
                block[..EXTERNAL_BYTES].copy_from_slice(&bytes);
                block[EXTERNAL_BYTES] = DOMAIN_EXTERNAL;
                seed.absorb_block(&block);
                wipe_bytes(&mut block);
                sources |= SOURCE_EXTERNAL;
                if credited < need {
                    credited += EXTERNAL_BYTES as u32 * external.credit_eighths.min(8);
                }
            }
            wipe_bytes(&mut bytes);
        }

        // 5. The events stirred in since the last seed, as one digest.
        if self.events_pending > 0 {
            self.events.finish(DOMAIN_SHA3);
            self.events.squeeze(&mut block[..32]);
            self.events.wipe();
            block[32] = DOMAIN_EVENTS;
            block[33..41].copy_from_slice(&self.events_pending.to_le_bytes());
            seed.absorb_block(&block);
            wipe_bytes(&mut block);
            sources |= SOURCE_EVENTS;
            self.events_pending = 0;
        }

        if credited < need {
            seed.wipe();
            return Err(self.jitter_error());
        }

        // Condition: the sponge's output is the XDRBG seed material; the
        // additional input binds the reseed count, the sources and the OSR.
        let mut material = [0u8; STATE_LEN];
        seed.finish(DOMAIN_SHAKE);
        seed.squeeze(&mut material);
        seed.wipe();
        let mut alpha = [0u8; 16];
        alpha[..8].copy_from_slice(&self.reseeds.to_le_bytes());
        alpha[8..12].copy_from_slice(&sources.to_le_bytes());
        alpha[12..].copy_from_slice(&self.jitter.osr().to_le_bytes());
        if self.drbg.is_seeded() {
            self.drbg.reseed(&material, &alpha);
        } else {
            self.drbg.instantiate(&material, &alpha);
        }
        wipe_bytes(&mut material);

        // A new key for the output stage, from the new XDRBG state. The
        // stage's nonce counter is not touched.
        let mut key = [0u8; 32];
        self.drbg.generate(&mut key, STREAM_KEY_LABEL);
        self.stream.rekey(&key);
        wipe_bytes(&mut key);

        self.reseeds += 1;
        self.since_reseed = 0;
        self.last_sources = sources;
        Ok(())
    }

    /// The most informative error when no seed could be credited: the
    /// jitter source's own failure if it has one.
    fn jitter_error(&self) -> RngError {
        match self.jitter_state {
            JitterState::Failed(error) => error,
            _ => RngError::NoSource,
        }
    }
}

/// One hardware word as its own block: word(8) | domain(1).
fn absorb_word(seed: &mut Sponge, block: &mut [u8; RATE], domain: u8, word: u64) {
    block[..8].copy_from_slice(&word.to_le_bytes());
    block[8] = domain;
    seed.absorb_block(block);
    wipe_bytes(block);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{jitter::DEFAULT_REGION_LEN, FLAG_READY};

    fn pool(region: &mut [u8]) -> EntropyPool<'_> {
        EntropyPool::new(region, Config::DEFAULT).unwrap()
    }

    #[test]
    fn a_host_pool_starts_seeds_and_reads() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        assert_eq!(p.fill(&mut a, Mode::Fast), Ok(100));
        assert_eq!(p.fill(&mut b, Mode::Fast), Ok(100));
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 100]);
        let s = p.status();
        assert_ne!(s.flags & FLAG_READY, 0);
        assert_ne!(s.sources & SOURCE_JITTER, 0, "the host timer should credit the seed");
        assert_eq!(s.bytes_out, 200);
        assert_eq!(s.reseeds, 1);
    }

    #[test]
    fn true_mode_reseeds_every_block() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        p.start().unwrap();
        let before = p.status().reseeds;
        let mut out = [0u8; 70];
        p.fill(&mut out, Mode::True).unwrap();
        // 70 bytes is three blocks: 32 + 32 + 6.
        assert_eq!(p.status().reseeds, before + 3);
    }

    #[test]
    fn stirred_events_reach_the_next_seed() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        p.start().unwrap();
        for i in 0..20 {
            p.stir(crate::rng::EVENT_KEY, i);
        }
        let mut out = [0u8; 8];
        p.fill(&mut out, Mode::True).unwrap();
        assert_ne!(p.status().sources & SOURCE_EVENTS, 0);
        assert_eq!(p.status().events, 20);
    }

    #[test]
    fn the_output_stage_uses_one_nonce_per_chunk_and_never_rewinds() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        let mut out = vec![0u8; 3 * CHUNK + 5];
        p.fill(&mut out, Mode::Fast).unwrap();
        assert_eq!(p.status().nonces, 4);
        // A reseed rekeys the stage but keeps counting.
        p.fill(&mut [0u8; 32], Mode::True).unwrap();
        p.fill(&mut [0u8; 10], Mode::Fast).unwrap();
        assert_eq!(p.status().nonces, 5);
    }

    #[test]
    fn a_burst_of_events_is_folded_in_before_the_next_fast_read() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        p.start().unwrap();
        for i in 0..EVENT_FOLD {
            p.stir(crate::rng::EVENT_USB, i);
        }
        let reseeds = p.status().reseeds;
        p.fill(&mut [0u8; 16], Mode::Fast).unwrap();
        assert_eq!(p.events_pending, 0, "the events went into the generator");
        assert_eq!(p.status().reseeds, reseeds, "a fold is not a credited reseed");
    }

    #[test]
    fn chacha20_can_be_chosen_on_purpose() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let config = Config { engine: EngineChoice::Software, ..Config::DEFAULT };
        let mut p = EntropyPool::new(&mut region, config).unwrap();
        p.fill(&mut [0u8; 16], Mode::Fast).unwrap();
        assert_eq!(p.engine(), Engine::ChaCha20);
        assert_eq!(p.status().engine, Engine::ChaCha20 as u32);
    }

    #[test]
    fn a_pool_without_any_credited_source_refuses_to_read() {
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        // Force the jitter source out and remove the hardware ones.
        p.selftest().unwrap();
        p.jitter_state = JitterState::Failed(RngError::Timer);
        p.hw = HwRng::absent();
        p.state = PoolState::Ready;
        let mut out = [0xAAu8; 16];
        assert_eq!(p.fill(&mut out, Mode::True), Err(RngError::Timer));
        assert_eq!(out, [0u8; 16], "no partial output on failure");
    }

    #[test]
    fn an_external_source_can_carry_a_degraded_seed() {
        fn constant(buf: &mut [u8]) -> bool {
            buf.fill(0x5A);
            true
        }
        let mut region = vec![0u8; DEFAULT_REGION_LEN];
        let mut p = pool(&mut region);
        p.set_external(Some(External { read: constant, credit_eighths: 8 }));
        p.selftest().unwrap();
        p.jitter_state = JitterState::Failed(RngError::Timer);
        p.hw = HwRng::absent();
        p.state = PoolState::Ready;
        let mut out = [0u8; 16];
        assert_eq!(p.fill(&mut out, Mode::True), Ok(16));
        let s = p.status();
        assert_ne!(s.flags & FLAG_DEGRADED, 0);
        assert_eq!(s.sources & SOURCE_JITTER, 0);
    }
}

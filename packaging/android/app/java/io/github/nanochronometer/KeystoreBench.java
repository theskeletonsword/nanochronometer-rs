// SPDX-License-Identifier: Apache-2.0
package io.github.nanochronometer;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * How long the secure hardware takes to answer, through the only door an app
 * has to it: the AndroidKeyStore provider, which reaches KeyMint (Keymaster
 * on older devices) in the TEE, or the StrongBox secure element.
 *
 * Every operation is a round trip — app, keystore2 daemon, HAL, secure world
 * and back — so these are latencies of that whole path, not of the cipher.
 * Keys are created for the run and deleted after it. Each key's security
 * level is read back, because asking for StrongBox and getting it are
 * different things, and a TEE number labelled StrongBox would be worse than
 * no number.
 */
final class KeystoreBench {
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String PREFIX = "nanochrono-bench-";

    interface Log {
        void line(String text);
    }

    private final Context context;
    private final Log log;

    KeystoreBench(Context context, Log log) {
        this.context = context;
        this.log = log;
    }

    static boolean hasStrongBox(Context context) {
        return Build.VERSION.SDK_INT >= 28
                && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    void run() {
        log.line("device: " + Build.MANUFACTURER + " " + Build.MODEL + ", API " + Build.VERSION.SDK_INT);
        if (Build.VERSION.SDK_INT >= 31) {
            PackageManager pm = context.getPackageManager();
            log.line("hardware keystore feature: "
                    + (pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) ? "yes" : "no"));
        }
        log.line("StrongBox feature: " + (hasStrongBox(context) ? "yes" : "no"));
        log.line("");
        backing(false);
        if (hasStrongBox(context)) {
            backing(true);
        } else {
            log.line("== StrongBox: not on this device (needs API 28 and a secure element)");
        }
        cleanup();
    }

    private void backing(boolean strongBox) {
        String name = strongBox ? "StrongBox" : "TEE";
        int n = strongBox ? 10 : 30;
        log.line("== " + name + " (" + n + " runs per operation; ms: min / median / max)");
        try {
            ecdsa(strongBox, n);
        } catch (Exception e) {
            log.line("  ECDSA P-256: " + describe(e));
        }
        try {
            rsaKeygen(strongBox);
        } catch (Exception e) {
            log.line("  RSA-2048 keygen: " + describe(e));
        }
        try {
            aesGcm(strongBox, n);
        } catch (Exception e) {
            log.line("  AES-256-GCM: " + describe(e));
        }
        try {
            hmac(strongBox, n);
        } catch (Exception e) {
            log.line("  HMAC-SHA256: " + describe(e));
        }
        log.line("");
    }

    private static String describe(Exception e) {
        if (e instanceof StrongBoxUnavailableException) {
            return "StrongBox refused this key type";
        }
        return e.getClass().getSimpleName() + ": " + e.getMessage();
    }

    private KeyGenParameterSpec.Builder spec(String alias, int purposes, boolean strongBox) {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes);
        if (strongBox && Build.VERSION.SDK_INT >= 28) {
            b.setIsStrongBoxBacked(true);
        }
        return b;
    }

    private void ecdsa(boolean strongBox, int n) throws Exception {
        String alias = PREFIX + "ec-" + strongBox;
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER);
        g.initialize(spec(alias, KeyProperties.PURPOSE_SIGN, strongBox)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        long t0 = System.nanoTime();
        KeyPair pair = g.generateKeyPair();
        long keygen = System.nanoTime() - t0;
        log.line("  ECDSA P-256 keygen: " + ms(keygen) + "  [" + level(pair.getPrivate()) + "]");

        byte[] message = new byte[32];
        long[] samples = new long[n];
        for (int i = 0; i < n; i++) {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(pair.getPrivate());
            s.update(message);
            long t = System.nanoTime();
            s.sign();
            samples[i] = System.nanoTime() - t;
        }
        log.line("  ECDSA P-256 sign:   " + stats(samples));
    }

    private void rsaKeygen(boolean strongBox) throws Exception {
        String alias = PREFIX + "rsa-" + strongBox;
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PROVIDER);
        g.initialize(spec(alias, KeyProperties.PURPOSE_SIGN, strongBox)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build());
        long t0 = System.nanoTime();
        KeyPair pair = g.generateKeyPair();
        long keygen = System.nanoTime() - t0;
        log.line("  RSA-2048 keygen:    " + ms(keygen) + "  [" + level(pair.getPrivate()) + "]");
    }

    private void aesGcm(boolean strongBox, int n) throws Exception {
        String alias = PREFIX + "aes-" + strongBox;
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        g.init(spec(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT, strongBox)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build());
        SecretKey key = g.generateKey();
        byte[] block = new byte[1024];
        long[] samples = new long[n];
        for (int i = 0; i < n; i++) {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            long t = System.nanoTime();
            c.init(Cipher.ENCRYPT_MODE, key);
            c.doFinal(block);
            samples[i] = System.nanoTime() - t;
        }
        log.line("  AES-256-GCM 1 KiB:  " + stats(samples) + "  [" + level(key) + "]");
    }

    private void hmac(boolean strongBox, int n) throws Exception {
        String alias = PREFIX + "hmac-" + strongBox;
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER);
        g.init(spec(alias, KeyProperties.PURPOSE_SIGN, strongBox).build());
        SecretKey key = g.generateKey();
        byte[] message = new byte[64];
        long[] samples = new long[n];
        for (int i = 0; i < n; i++) {
            Mac mac = Mac.getInstance("HmacSHA256");
            long t = System.nanoTime();
            mac.init(key);
            mac.doFinal(message);
            samples[i] = System.nanoTime() - t;
        }
        log.line("  HMAC-SHA256 64 B:   " + stats(samples) + "  [" + level(key) + "]");
    }

    /** Where the key actually lives, as the keystore reports it. */
    private static String level(Key key) {
        try {
            KeyInfo info;
            if (key instanceof PrivateKey) {
                info = KeyFactory.getInstance(key.getAlgorithm(), PROVIDER).getKeySpec(key, KeyInfo.class);
            } else {
                info = (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), PROVIDER)
                        .getKeySpec((SecretKey) key, KeyInfo.class);
            }
            if (Build.VERSION.SDK_INT >= 31) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX: return "StrongBox";
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "TEE";
                    case KeyProperties.SECURITY_LEVEL_SOFTWARE: return "SOFTWARE";
                    default: return "unknown level";
                }
            }
            @SuppressWarnings("deprecation")
            boolean hw = info.isInsideSecureHardware();
            return hw ? "secure hardware" : "SOFTWARE";
        } catch (Exception e) {
            return "level unreadable";
        }
    }

    private static String ms(long ns) {
        return String.format(Locale.ROOT, "%.3f ms", ns / 1e6);
    }

    private static String stats(long[] samples) {
        long[] s = samples.clone();
        Arrays.sort(s);
        return String.format(Locale.ROOT, "%.3f / %.3f / %.3f",
                s[0] / 1e6, s[s.length / 2] / 1e6, s[s.length - 1] / 1e6);
    }

    private void cleanup() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            for (String alias : java.util.Collections.list(ks.aliases())) {
                if (alias.startsWith(PREFIX)) {
                    ks.deleteEntry(alias);
                }
            }
        } catch (Exception e) {
            log.line("cleanup: " + describe(e));
        }
    }
}

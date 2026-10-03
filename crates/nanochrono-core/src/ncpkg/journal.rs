// SPDX-License-Identifier: Apache-2.0
//! The transaction journal, `/var/lib/ncpkg/journal.json`.
//!
//! Written (atomically) before a transaction touches anything outside its
//! own staging directory, it lists every step in the order the steps run,
//! each one a single atomic rename or directory creation that can be told
//! apart, after a crash, as done or not done:
//!
//! ```json
//! {
//!   "format": "ncpkg-journal/1",
//!   "tx": "0000000000000008-5a17c0de00000000",
//!   "op": "install",
//!   "package": "org.example.player-plus",
//!   "steps": [
//!     {"backup": {"from": "/usr/lib/libavcodec.ncdyn", "to": "/var/lib/ncpkg/tx/…/backup/0"}},
//!     {"mkdir": "/apps/org.example.player-plus"},
//!     {"place": {"from": "/var/lib/ncpkg/tx/…/stage/0", "to": "/apps/org.example.player-plus/main.ncapp"}}
//!   ],
//!   "cleanup": ["/apps/org.example.old/res", "/apps/org.example.old"]
//! }
//! ```
//!
//! Undoing is the steps backwards: a placed file goes back to the stage, a
//! backed-up file back to where it was, a created directory away if empty.
//! Finishing is deleting the backups and the stage, then the directories in
//! `cleanup` that ended up empty. Which of the two recovery does is decided
//! by the database, not the journal — see [`super::manager`].

use crate::json::{self, Json, Kind, Style, Value};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const FORMAT: &str = "ncpkg-journal/1";
pub const PATH: &str = "/var/lib/ncpkg/journal.json";
/// Staging and backups live under `<TX_DIR>/<tx>/`.
pub const TX_DIR: &str = "/var/lib/ncpkg/tx";

/// One atomic step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create a directory that did not exist.
    Mkdir(String),
    /// Move an existing file aside, into the transaction's backups.
    Backup { from: String, to: String },
    /// Move a staged file into place, where nothing is.
    Place { from: String, to: String },
}

/// A transaction as the journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    pub tx: String,
    /// `install`, `upgrade`, `reinstall` or `remove`.
    pub op: String,
    pub package: String,
    pub steps: Vec<Step>,
    /// Directories to remove after the commit if they ended up empty,
    /// deepest first.
    pub cleanup: Vec<String>,
}

impl Journal {
    /// The transaction's own directory.
    pub fn tx_dir(&self) -> String {
        format!("{TX_DIR}/{}", self.tx)
    }

    pub fn to_json(&self) -> String {
        let pair = |from: &str, to: &str| Json::obj([("from", Json::str(from)), ("to", Json::str(to))]);
        let steps = self
            .steps
            .iter()
            .map(|s| match s {
                Step::Mkdir(p) => Json::obj([("mkdir", Json::str(p))]),
                Step::Backup { from, to } => Json::obj([("backup", pair(from, to))]),
                Step::Place { from, to } => Json::obj([("place", pair(from, to))]),
            })
            .collect();
        Json::obj([
            ("format", Json::str(FORMAT)),
            ("tx", Json::str(&self.tx)),
            ("op", Json::str(&self.op)),
            ("package", Json::str(&self.package)),
            ("steps", Json::Arr(steps)),
            ("cleanup", Json::Arr(self.cleanup.iter().map(|c| Json::str(c)).collect())),
        ])
        .write(Style::PRETTY)
    }

    pub fn parse(bytes: &[u8]) -> Result<Journal, String> {
        let root = json::parse(bytes, &json::Limits::DATABASE).map_err(|e| format!("journal is not valid JSON: {e}"))?;
        let get = |v: Value<'_>, k: &str| -> Result<String, String> {
            Ok(v.get(k).and_then(|s| s.as_str()).ok_or_else(|| format!("journal: {k} missing"))?.to_string())
        };
        if get(root, "format")? != FORMAT {
            return Err(String::from("journal: unknown format"));
        }
        let path_ok = |p: &str| super::path::is_system_path(p);
        let mut steps = Vec::new();
        let list = root.get("steps").filter(|v| v.kind() == Kind::Array).ok_or("journal: steps missing")?;
        for s in list.elements() {
            let (key, body) = s.members().next().ok_or("journal: empty step")?;
            let step = if key.eq_str("mkdir") {
                Step::Mkdir(body.as_str().ok_or("journal: bad mkdir")?.to_string())
            } else if key.eq_str("backup") || key.eq_str("place") {
                let (from, to) = (get(body, "from")?, get(body, "to")?);
                if key.eq_str("backup") {
                    Step::Backup { from, to }
                } else {
                    Step::Place { from, to }
                }
            } else {
                return Err(String::from("journal: unknown step"));
            };
            let ok = match &step {
                Step::Mkdir(p) => path_ok(p),
                Step::Backup { from, to } | Step::Place { from, to } => path_ok(from) && path_ok(to),
            };
            if !ok {
                return Err(String::from("journal: a step names a path outside the installer's alphabet"));
            }
            steps.push(step);
        }
        let cleanup = root
            .get("cleanup")
            .filter(|v| v.kind() == Kind::Array)
            .ok_or("journal: cleanup missing")?
            .elements()
            .map(|c| c.as_str().map(|s| s.to_string()).filter(|s| path_ok(s)).ok_or_else(|| String::from("journal: bad cleanup entry")))
            .collect::<Result<Vec<_>, _>>()?;
        let tx = get(root, "tx")?;
        if !super::path::is_component(&tx) {
            return Err(String::from("journal: bad transaction id"));
        }
        Ok(Journal { tx, op: get(root, "op")?, package: get(root, "package")?, steps, cleanup })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let j = Journal {
            tx: String::from("0000000000000001-0000000000000002"),
            op: String::from("install"),
            package: String::from("org.a.one"),
            steps: alloc::vec![
                Step::Backup { from: String::from("/usr/lib/libfoo.ncdyn"), to: String::from("/var/lib/ncpkg/tx/x/backup/0") },
                Step::Mkdir(String::from("/apps/org.a.one")),
                Step::Place { from: String::from("/var/lib/ncpkg/tx/x/stage/0"), to: String::from("/apps/org.a.one/main.ncapp") },
            ],
            cleanup: alloc::vec![String::from("/apps/org.a.old")],
        };
        assert_eq!(Journal::parse(j.to_json().as_bytes()).unwrap(), j);
        let evil = j.to_json().replace("/apps/org.a.one/main.ncapp", "/apps/../etc/passwd");
        assert!(Journal::parse(evil.as_bytes()).is_err());
    }
}

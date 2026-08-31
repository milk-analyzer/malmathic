use std::collections::HashSet;
use std::io::{Read, Seek};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};
use ntfs_core::usn::UsnRecord;

use crate::Volume;

pub const JOURNAL_PATH: &str = "\\$Extend\\$UsnJrnl";

pub const STREAM_J: &str = "$J";

pub const STREAM_MAX: &str = "$Max";

pub const MAX_RECORDS: usize = 2_000_000;

pub const MAX_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;

pub const TIME_BUDGET: Duration = Duration::from_secs(90);

const WINDOW: usize = 1024 * 1024;

const OVERLAP: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalMax {
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub journal_id: u64,
    pub created: Option<DateTime<Utc>>,
    pub lowest_valid_usn: i64,
}

impl JournalMax {
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let f = data.get(..32)?;
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&f[o..o + 8]);
            u64::from_le_bytes(b)
        };
        let journal_id = u64_at(0x10);
        Some(JournalMax {
            maximum_size: u64_at(0x00),
            allocation_delta: u64_at(0x08),
            journal_id,
            created: filetime(journal_id as i64),
            lowest_valid_usn: u64_at(0x18) as i64,
        })
    }
}

fn filetime(ticks: i64) -> Option<DateTime<Utc>> {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    const CEILING: i64 = 283_694_198_400_000_000;
    if ticks <= 0 || ticks >= CEILING {
        return None;
    }
    let unix = ticks - EPOCH_DIFF;
    if unix < 0 {
        return None;
    }
    Utc.timestamp_opt(unix / 10_000_000, ((unix % 10_000_000) * 100) as u32).single()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Truncation {
    Records(usize),
    Bytes(u64),
    Time(u64),
    ReadError(String),
}

impl Truncation {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Truncation::Records(n) => {
                format!("it reached its limit of {n} records; older events were not read")
            }
            Truncation::Bytes(b) => format!(
                "it reached its limit of {} MiB of journal read; older events were not read",
                b / (1024 * 1024)
            ),
            Truncation::Time(s) => {
                format!("it ran out of its {s}-second budget; older events were not read")
            }
            Truncation::ReadError(e) => {
                format!(
                    "a cluster read failed ({e}); how much of the journal is missing is unknown"
                )
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    NoJournal,
    Active { records: usize },
    EmptyOrCleared { reason: String },
}

#[derive(Clone, Debug)]
pub struct Journal {
    pub max: Option<JournalMax>,
    pub records: Vec<UsnRecord>,
    pub allocated_bytes: u64,
    pub sparse_bytes: u64,
    pub bytes_read: u64,
    pub truncated: Option<Truncation>,
    pub elapsed: Duration,
}

impl Journal {
    #[must_use]
    pub fn window(&self) -> Window {
        let mut w = Window::default();
        for r in &self.records {
            w.first_usn = Some(w.first_usn.map_or(r.usn, |v: i64| v.min(r.usn)));
            w.last_usn = Some(w.last_usn.map_or(r.usn, |v: i64| v.max(r.usn)));
            w.first_time =
                Some(w.first_time.map_or(r.timestamp, |v: DateTime<Utc>| v.min(r.timestamp)));
            w.last_time =
                Some(w.last_time.map_or(r.timestamp, |v: DateTime<Utc>| v.max(r.timestamp)));
        }
        w
    }

    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if self.max.is_none() && self.records.is_empty() && self.allocated_bytes == 0 {
            return Verdict::NoJournal;
        }
        if self.records.is_empty() {
            let reason = if self.allocated_bytes == 0 {
                "the $J stream has no allocated clusters at all".to_string()
            } else {
                format!(
                    "{} KiB of $J is allocated but no record decoded from it",
                    self.allocated_bytes / 1024
                )
            };
            return Verdict::EmptyOrCleared { reason };
        }
        Verdict::Active { records: self.records.len() }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub first_usn: Option<i64>,
    pub last_usn: Option<i64>,
    pub first_time: Option<DateTime<Utc>>,
    pub last_time: Option<DateTime<Utc>>,
}

pub fn read_journal<R: Read + Seek>(vol: &Volume<R>) -> Journal {
    let started = Instant::now();
    let mut journal = Journal {
        max: None,
        records: Vec::new(),
        allocated_bytes: 0,
        sparse_bytes: 0,
        bytes_read: 0,
        truncated: None,
        elapsed: Duration::ZERO,
    };

    let Some(record) = vol.resolve(JOURNAL_PATH) else {
        journal.elapsed = started.elapsed();
        return journal;
    };

    if let Ok(bytes) = vol.fs().read_data_by_record(record, Some(STREAM_MAX), 4096) {
        journal.max = JournalMax::parse(&bytes);
    }

    let cluster = vol.cluster_size();
    let runs = vol.fs().runs_by_record(record, Some(STREAM_J)).unwrap_or_default();
    for run in &runs {
        let bytes = run.length.saturating_mul(cluster);
        if run.lcn.is_some() {
            journal.allocated_bytes = journal.allocated_bytes.saturating_add(bytes);
        } else {
            journal.sparse_bytes = journal.sparse_bytes.saturating_add(bytes);
        }
    }

    let mut segments: Vec<Vec<(u64, u64)>> = Vec::new();
    let mut current: Vec<(u64, u64)> = Vec::new();
    for run in &runs {
        match run.lcn {
            Some(lcn) if run.length > 0 => current.push((lcn, run.length)),
            _ => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }

    let mut seen: HashSet<i64> = HashSet::new();
    'outer: for segment in segments {
        let mut carry: Vec<u8> = Vec::new();
        for (lcn, length) in segment {
            let mut done = 0u64;
            while done < length {
                if let Some(stop) = exhausted(&journal, started) {
                    journal.truncated = Some(stop);
                    break 'outer;
                }
                let want = ((length - done) as usize).min(WINDOW / cluster.max(1) as usize).max(1);
                let mut buf = vec![0u8; want * cluster as usize];
                if let Err(e) = vol.read_clusters(lcn + done, &mut buf) {
                    journal.truncated = Some(Truncation::ReadError(e.to_string()));
                    break 'outer;
                }
                journal.bytes_read = journal.bytes_read.saturating_add(buf.len() as u64);
                done += want as u64;

                let scan = if carry.is_empty() {
                    buf
                } else {
                    let mut joined = std::mem::take(&mut carry);
                    joined.extend_from_slice(&buf);
                    joined
                };
                let (carved, _stats) = ntfs_core::usn::carve_usn_records(&scan);
                for c in carved {
                    if seen.insert(c.record.usn) {
                        journal.records.push(c.record);
                        if journal.records.len() >= MAX_RECORDS {
                            journal.truncated = Some(Truncation::Records(MAX_RECORDS));
                            break 'outer;
                        }
                    }
                }
                let keep = scan.len().min(OVERLAP);
                carry = scan[scan.len() - keep..].to_vec();
            }
        }
    }

    journal.records.sort_by_key(|r| r.usn);
    journal.elapsed = started.elapsed();
    journal
}

fn exhausted(journal: &Journal, started: Instant) -> Option<Truncation> {
    if journal.records.len() >= MAX_RECORDS {
        return Some(Truncation::Records(MAX_RECORDS));
    }
    if journal.bytes_read >= MAX_JOURNAL_BYTES {
        return Some(Truncation::Bytes(MAX_JOURNAL_BYTES));
    }
    if started.elapsed() >= TIME_BUDGET {
        return Some(Truncation::Time(TIME_BUDGET.as_secs()));
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordFate {
    SameFile,
    Freed,
    Reallocated { journal_sequence: u16, live_sequence: u16, now_name: Option<String> },
    Unknown { reason: String },
}

impl RecordFate {
    #[must_use]
    pub fn carving_is_sound(&self) -> bool {
        matches!(self, RecordFate::SameFile | RecordFate::Freed)
    }

    #[must_use]
    pub fn describe(&self, entry: u64) -> String {
        match self {
            RecordFate::SameFile => {
                format!("$MFT record {entry} still holds this file")
            }
            RecordFate::Freed => format!(
                "$MFT record {entry} is free but has not been reused, so its runlist still \
                 describes this file"
            ),
            RecordFate::Reallocated { journal_sequence, live_sequence, now_name } => {
                let taken =
                    now_name.as_deref().map_or(String::new(), |n| format!(" — it now holds {n}"));
                format!(
                    "$MFT record {entry} has been REALLOCATED: the journal names it at sequence \
                     {journal_sequence}, the volume now carries sequence {live_sequence}{taken}. \
                     Nothing of this file survives in that record"
                )
            }
            RecordFate::Unknown { reason } => {
                format!("$MFT record {entry} could not be read ({reason}), so its fate is unknown")
            }
        }
    }
}

pub fn record_fate<R: Read + Seek>(vol: &Volume<R>, entry: u64, sequence: u16) -> RecordFate {
    let bytes = match vol.fs().read_record(entry) {
        Ok(b) => b,
        Err(e) => return RecordFate::Unknown { reason: e.to_string() },
    };
    let header = match ntfs_core::MftRecordHeader::parse(&bytes) {
        Ok(h) => h,
        Err(e) => return RecordFate::Unknown { reason: e.to_string() },
    };
    if &header.signature != b"FILE" {
        return RecordFate::Unknown {
            reason: format!("record signature is {:?}, not FILE", header.signature),
        };
    }
    if header.sequence_number != sequence {
        return RecordFate::Reallocated {
            journal_sequence: sequence,
            live_sequence: header.sequence_number,
            now_name: vol.record_identity(entry).map(|i| i.name),
        };
    }
    if header.is_in_use() {
        RecordFate::SameFile
    } else {
        RecordFate::Freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWIN7_MAX: [u8; 32] = [
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xaa, 0xe3, 0x4c, 0xc4, 0x7b, 0x39, 0xdc, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn max_decodes_the_bytes_a_real_volume_carries() {
        let m = JournalMax::parse(&SWIN7_MAX).expect("32 bytes is enough");
        assert_eq!(m.maximum_size, 32 * 1024 * 1024);
        assert_eq!(m.allocation_delta, 4 * 1024 * 1024);
        assert_eq!(m.lowest_valid_usn, 0);
        let created = m.created.expect("journal id decodes as a moment");
        assert!(
            created.format("%Y").to_string().starts_with("20"),
            "journal created {created} is not a plausible moment"
        );
    }

    #[test]
    fn a_short_max_is_unknown_rather_than_guessed() {
        assert_eq!(JournalMax::parse(&[]), None);
        assert_eq!(JournalMax::parse(&SWIN7_MAX[..31]), None);
        assert!(JournalMax::parse(&SWIN7_MAX[..32]).is_some());
    }

    #[test]
    fn implausible_filetimes_are_unknown() {
        assert_eq!(filetime(0), None);
        assert_eq!(filetime(-1), None);
        assert_eq!(filetime(i64::MAX), None);
        assert_eq!(filetime(1), None);
        assert!(filetime(133_500_480_000_000_000).is_some());
    }

    #[test]
    fn an_absent_journal_is_not_a_cleared_one() {
        let empty = Journal {
            max: None,
            records: Vec::new(),
            allocated_bytes: 0,
            sparse_bytes: 0,
            bytes_read: 0,
            truncated: None,
            elapsed: Duration::ZERO,
        };
        assert_eq!(empty.verdict(), Verdict::NoJournal);

        let cleared = Journal { max: JournalMax::parse(&SWIN7_MAX), ..empty.clone() };
        assert!(matches!(cleared.verdict(), Verdict::EmptyOrCleared { .. }));

        let allocated_but_silent = Journal { allocated_bytes: 64 * 1024, ..empty };
        match allocated_but_silent.verdict() {
            Verdict::EmptyOrCleared { reason } => assert!(reason.contains("64 KiB")),
            other => panic!("expected EmptyOrCleared, got {other:?}"),
        }
    }

    #[test]
    fn only_an_unreused_record_may_be_carved_from() {
        assert!(RecordFate::SameFile.carving_is_sound());
        assert!(RecordFate::Freed.carving_is_sound());
        assert!(!RecordFate::Reallocated {
            journal_sequence: 5,
            live_sequence: 6,
            now_name: Some("other.txt".into())
        }
        .carving_is_sound());
        assert!(!RecordFate::Unknown { reason: "unreadable".into() }.carving_is_sound());
    }

    #[test]
    fn a_reallocation_states_both_sequences() {
        let fate = RecordFate::Reallocated {
            journal_sequence: 5,
            live_sequence: 6,
            now_name: Some("PfSvPerfStats.bin".into()),
        };
        let s = fate.describe(41_977);
        assert!(s.contains("41977"), "{s}");
        assert!(s.contains("REALLOCATED"), "{s}");
        assert!(s.contains("sequence 5"), "{s}");
        assert!(s.contains("sequence 6"), "{s}");
        assert!(s.contains("PfSvPerfStats.bin"), "{s}");
        let unknown = RecordFate::Unknown { reason: "short read".into() }.describe(7);
        assert!(unknown.contains("unknown"), "{unknown}");
        assert!(!unknown.contains("REALLOCATED"), "{unknown}");
    }

    #[test]
    fn every_truncation_says_what_was_not_read() {
        for t in [
            Truncation::Records(10),
            Truncation::Bytes(512 * 1024 * 1024),
            Truncation::Time(90),
            Truncation::ReadError("device not ready".into()),
        ] {
            let s = t.describe();
            assert!(
                s.contains("not read") || s.contains("unknown"),
                "truncation {t:?} does not admit to missing evidence: {s}"
            );
        }
    }

    #[test]
    fn an_empty_journal_has_no_window() {
        let j = Journal {
            max: None,
            records: Vec::new(),
            allocated_bytes: 0,
            sparse_bytes: 0,
            bytes_read: 0,
            truncated: None,
            elapsed: Duration::ZERO,
        };
        let w = j.window();
        assert_eq!(w.first_usn, None);
        assert_eq!(w.last_usn, None);
        assert_eq!(w.first_time, None);
        assert_eq!(w.last_time, None);
    }
}

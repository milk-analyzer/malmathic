use std::collections::HashMap;
use std::io::{Read, Seek};

use mm_core::{
    Acquisition, ArtifactSource, Candidate, FileHash, NormalizedPath, ObservationKind, Recovery,
};
use mm_harvest::filesystem::OrphanedDeleted;
use mm_harvest::quarantine::{self, QuarantinedFile};
use mm_raw::ghost::Ghost;
use mm_raw::{Fate, Run, Volume};

use crate::index_slack::RecoveredNames;

#[derive(Clone, Debug)]
pub struct SampleDir {
    pub path: std::path::PathBuf,
    pub relative: &'static str,
    pub write_out: bool,
}

pub const MAX_SAMPLE_BYTES: usize = 256 * 1024 * 1024;
const _: () =
    assert!(MAX_SAMPLE_BYTES >= 64 * 1024 * 1024 && MAX_SAMPLE_BYTES <= 512 * 1024 * 1024);

const BITMAP_RECORD: u64 = 6;

pub const MAX_BITMAP_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_LOG_FILE_BYTES: usize = 256 * 1024 * 1024;

const MAX_GHOSTS: usize = 200_000;

const MAX_GHOST_NAMES: usize = 50_000;

pub const QUARANTINE_RESOURCE_DATA: &str =
    "\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\ResourceData";

#[derive(Debug, Default)]
pub struct QuarantineStore {
    by_path: HashMap<String, QuarantinedFile>,
}

impl QuarantineStore {
    pub fn new() -> Self {
        QuarantineStore::default()
    }

    pub fn add(&mut self, files: impl IntoIterator<Item = QuarantinedFile>) {
        for file in files {
            self.by_path.entry(file.path.key().to_string()).or_insert(file);
        }
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    fn lookup(&self, path: &NormalizedPath) -> Option<&QuarantinedFile> {
        self.by_path.get(path.key())
    }
}

#[derive(Debug, Default)]
pub struct RecycleBinStore {
    by_original: HashMap<String, RecycledPointer>,
}

#[derive(Clone, Debug)]
pub struct RecycledPointer {
    pub data_path: String,
    pub info_path: String,
    pub original_raw: String,
    pub claimed_size: u64,
    pub deleted: Option<String>,
    pub layout: &'static str,
}

impl RecycleBinStore {
    pub fn new() -> Self {
        RecycleBinStore::default()
    }

    pub fn add(&mut self, original: &NormalizedPath, pointer: RecycledPointer) {
        self.by_original.entry(original.key().to_string()).or_insert(pointer);
    }

    pub fn len(&self) -> usize {
        self.by_original.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_original.is_empty()
    }

    fn lookup(&self, path: &NormalizedPath) -> Option<&RecycledPointer> {
        self.by_original.get(path.key())
    }
}

#[derive(Debug, Default)]
pub struct ClusterMap {
    bits: Option<Vec<u8>>,
    attempted: bool,
}

impl ClusterMap {
    pub fn new() -> Self {
        ClusterMap::default()
    }

    pub(crate) fn bits(&mut self, volume: &Volume<impl Read + Seek>) -> Option<&[u8]> {
        if !self.attempted {
            self.attempted = true;
            self.bits = volume
                .read_record_capped(BITMAP_RECORD, MAX_BITMAP_BYTES)
                .ok()
                .filter(|bits| bitmap_is_credible(bits));
        }
        self.bits.as_deref()
    }

    fn allocation(
        &mut self,
        volume: &Volume<impl Read + Seek>,
        runs: &[Run],
    ) -> Option<Allocation> {
        let bits = self.bits(volume)?;
        let described = (bits.len() as u64).saturating_mul(8);
        let mut budget = described;

        let mut allocation = Allocation::default();
        for run in runs {
            let Some(lcn) = run.lcn else {
                allocation.sparse = allocation.sparse.saturating_add(run.length);
                continue;
            };
            let reach = lcn.saturating_add(run.length).min(described);
            let walk = reach.saturating_sub(lcn).min(budget);
            for cluster in lcn..lcn.saturating_add(walk) {
                match bit(bits, cluster) {
                    Some(true) => allocation.reused = allocation.reused.saturating_add(1),
                    Some(false) => allocation.free = allocation.free.saturating_add(1),
                    None => allocation.unknown = allocation.unknown.saturating_add(1),
                }
            }
            budget -= walk;
            allocation.unknown = allocation.unknown.saturating_add(run.length.saturating_sub(walk));
        }
        Some(allocation)
    }
}

fn bitmap_is_credible(bits: &[u8]) -> bool {
    bit(bits, 0) == Some(true)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Allocation {
    free: u64,
    reused: u64,
    unknown: u64,
    sparse: u64,
}

impl Allocation {
    fn total(&self) -> u64 {
        self.free + self.reused + self.unknown + self.sparse
    }
}

pub(crate) fn bit(bits: &[u8], n: u64) -> Option<bool> {
    let byte = usize::try_from(n / 8).ok()?;
    Some(bits.get(byte)? & (1u8 << (n % 8)) != 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Volume,
    Quarantine,
    RecycleBin,
    ShadowCopy,
    CarvedClusters,
    IndexSlack,
    OrphanedRecord,
    RecordSlack,
    LogFileGhost,
}

impl Step {
    fn label(self) -> &'static str {
        match self {
            Step::Volume => "the file on the volume",
            Step::Quarantine => "the Defender quarantine",
            Step::RecycleBin => "the recycle bin",
            Step::ShadowCopy => "a volume shadow copy",
            Step::CarvedClusters => "the deleted file's own clusters",
            Step::IndexSlack => "a record the parent directory's index slack named",
            Step::OrphanedRecord => "an orphaned $MFT record",
            Step::RecordSlack => "the unused tail of a reused $MFT record",
            Step::LogFileGhost => "a record image still in $LogFile",
        }
    }
}

const CHAIN: [Step; 9] = [
    Step::Volume,
    Step::Quarantine,
    Step::RecycleBin,
    Step::ShadowCopy,
    Step::CarvedClusters,
    Step::IndexSlack,
    Step::OrphanedRecord,
    Step::RecordSlack,
    Step::LogFileGhost,
];

#[allow(clippy::too_many_arguments)]
fn run_step<R: Read + Seek>(
    step: Step,
    volume: &Volume<R>,
    quarantine: &QuarantineStore,
    recycle_bin: &RecycleBinStore,
    shadows: &ShadowStore<R>,
    orphans: &OrphanIndex,
    slack: &RecoveredNames,
    ghosts: &GhostIndex,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    match step {
        Step::Volume => from_volume(volume, clusters, candidate, sample_dir),
        Step::Quarantine => from_quarantine(volume, quarantine, candidate, sample_dir),
        Step::RecycleBin => from_recycle_bin(volume, recycle_bin, candidate, sample_dir),
        Step::ShadowCopy => from_shadow_copy(shadows, candidate, sample_dir),
        Step::CarvedClusters => from_carved_clusters(volume, clusters, candidate, sample_dir),
        Step::IndexSlack => from_index_slack(volume, clusters, slack, candidate, sample_dir),
        Step::OrphanedRecord => {
            from_orphaned_record(volume, clusters, orphans, candidate, sample_dir)
        }
        Step::RecordSlack => from_record_slack(volume, clusters, candidate, sample_dir),
        Step::LogFileGhost => from_log_file(volume, clusters, ghosts, candidate, sample_dir),
    }
}

#[derive(Clone)]
struct HashBookkeeping {
    hash: FileHash,
    acquired_hash: Option<FileHash>,
    hash_checks: Vec<mm_core::HashCheck>,
}

impl HashBookkeeping {
    fn of(candidate: &Candidate) -> Self {
        HashBookkeeping {
            hash: candidate.hash.clone(),
            acquired_hash: candidate.acquired_hash.clone(),
            hash_checks: candidate.hash_checks.clone(),
        }
    }

    fn restore(self, candidate: &mut Candidate) {
        candidate.hash = self.hash;
        candidate.acquired_hash = self.acquired_hash;
        candidate.hash_checks = self.hash_checks;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn acquire<R: Read + Seek>(
    volume: &Volume<R>,
    quarantine: &QuarantineStore,
    recycle_bin: &RecycleBinStore,
    shadows: &ShadowStore<R>,
    orphans: &OrphanIndex,
    slack: &RecoveredNames,
    ghosts: &GhostIndex,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Acquisition {
    let mut first_failure: Option<String> = None;
    let mut held: Option<(Step, HashBookkeeping)> = None;

    let something_could_confirm_it = candidate.recorded_hash().is_some();

    for step in CHAIN {
        let before = HashBookkeeping::of(candidate);
        match run_step(
            step,
            volume,
            quarantine,
            recycle_bin,
            shadows,
            orphans,
            slack,
            ghosts,
            clusters,
            candidate,
            sample_dir,
        ) {
            None => {}
            Some(Acquisition::Failed { reason }) => {
                first_failure.get_or_insert(reason);
            }
            Some(Acquisition::Bytes { via, size, saved_as, recovery })
                if recovery.is_trustworthy() =>
            {
                return Acquisition::Bytes { via, size, saved_as, recovery };
            }
            Some(Acquisition::Withheld { via, size, recovery }) if recovery.is_trustworthy() => {
                return Acquisition::Withheld { via, size, recovery };
            }
            Some(other) => {
                if !something_could_confirm_it {
                    return other;
                }
                if held.is_none() {
                    held = Some((step, before.clone()));
                }
                before.restore(candidate);
            }
        }
    }

    if let Some((step, at_the_time)) = held {
        at_the_time.restore(candidate);
        match run_step(
            step,
            volume,
            quarantine,
            recycle_bin,
            shadows,
            orphans,
            slack,
            ghosts,
            clusters,
            candidate,
            sample_dir,
        ) {
            Some(Acquisition::Bytes { via, size, saved_as, recovery }) => {
                return Acquisition::Bytes { via, size, saved_as, recovery }
            }
            Some(Acquisition::Withheld { via, size, recovery }) => {
                return Acquisition::Withheld { via, size, recovery }
            }
            other => {
                let reason = match other {
                    Some(Acquisition::Failed { reason }) => reason,
                    _ => format!(
                        "{} produced bytes that could not be confirmed, and would not produce \
                         them a second time — the volume changed underneath this run",
                        step.label()
                    ),
                };
                first_failure.get_or_insert(reason);
            }
        }
    }

    if let Some(a) = from_recorded_hash(candidate) {
        return a;
    }

    Acquisition::Failed {
        reason: first_failure.unwrap_or_else(|| fell_through_the_chain(candidate)),
    }
}

fn fell_through_the_chain(candidate: &Candidate) -> String {
    let Some(path) = candidate.path.as_ref().filter(|p| !p.raw().is_empty()) else {
        return "nothing identifies this candidate beyond the observations themselves".to_string();
    };

    match live_mft_record(candidate) {
        Some(record) => format!(
            "the $MFT walk found this file in record {record} and in use, but no acquisition \
             step would stand behind its bytes: the path does not resolve through the directory \
             indexes, and reading the record directly was refused because it no longer carries \
             this file's name, or is no longer in use, or $Bitmap has given its clusters away — \
             all of which mean the record was reused after the walk read it. No artifact \
             recorded a hash to fall back on. `diag mft --record {record} --image <image>` says \
             what that record holds now. Whether the file is still on this volume is UNKNOWN \
             from this run: what is known is that this record is no longer it"
        ),
        None => format!(
            "no bytes and no hash for {}: no $MFT record was read for this path, so the file is \
             not on this volume under this name; it was not in Defender's quarantine, the \
             recycle bin, or any shadow copy; no deleted record was left to carve; no record \
             carrying this name survived in the tail of a reused $MFT record or in $LogFile; \
             and no artifact recorded a hash of it",
            path.raw()
        ),
    }
}

fn from_volume<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let key = path.key().to_string();
    let (record, unlinked) = match volume.resolve(&key) {
        Some(record) => (record, None),
        None => {
            let (record, detail) = by_unlinked_record(volume, clusters, candidate)?;
            (record, Some(detail))
        }
    };

    if volume.is_efs_encrypted(record) {
        return Some(Acquisition::Failed {
            reason: "the file is present but EFS-encrypted (FILE_ATTRIBUTE_ENCRYPTED, with an \
                     $EFS stream holding the wrapped key), so its $DATA is ciphertext — it was \
                     not copied and not hashed, because a hash of the ciphertext is not this \
                     file's hash. Decrypting needs the owning user's DPAPI master key and \
                     password, which are not on this volume"
                .to_string(),
        });
    }

    let bytes = match volume.read_record_capped(record, MAX_SAMPLE_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!("present on the volume but unreadable: {e}"),
            })
        }
    };

    if bytes.len() >= MAX_SAMPLE_BYTES {
        let size = recorded_size(candidate);
        return Some(Acquisition::Failed {
            reason: format!(
                "the file is present but {}past the {} MB copy limit, so it was not copied and \
                 not hashed — a hash of the first {} MB is not this file's hash",
                size.map(|s| format!("{s} bytes, ")).unwrap_or_default(),
                MAX_SAMPLE_BYTES / (1024 * 1024),
                MAX_SAMPLE_BYTES / (1024 * 1024)
            ),
        });
    }

    let computed = FileHash::compute(&bytes);
    candidate.record_acquired_hash(&computed, true);

    let recovery = match unlinked {
        None => Recovery::Intact,
        Some(detail) => Recovery::UnlinkedButPresent { detail },
    };
    save(candidate, &bytes, sample_dir, ArtifactSource::Mft, recovery)
}

fn live_mft_record(candidate: &Candidate) -> Option<u64> {
    candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::FileExists { record, .. } => *record,
        _ => None,
    })
}

fn by_unlinked_record<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &Candidate,
) -> Option<(u64, String)> {
    let record = live_mft_record(candidate)?;
    let wanted = candidate.path.as_ref()?.file_name()?.to_lowercase();

    let identity = volume.record_identity(record)?;
    if !identity.in_use || identity.name.to_lowercase() != wanted {
        return None;
    }

    let runs = volume.data_runs(record);
    let allocation = clusters.allocation(volume, &runs);
    let owned = match &allocation {
        Some(a) if a.total() == 0 => "it is resident or sparse, so it occupies no clusters",
        Some(a) if a.free == 0 && a.unknown == 0 => {
            "and $Bitmap still marks every cluster of its $DATA allocated"
        }
        Some(_) => return None,
        None => {
            "though $Bitmap could not be read, so whether its clusters are still allocated \
                 is UNKNOWN"
        }
    };

    Some((
        record,
        format!(
            "read from $MFT record {record}, which is in use and carries this file's name, \
             {owned} — but the name is NOT in the index of the directory the record names as \
             its parent, so the path does not resolve. This is a fact about the volume, not \
             about the bytes: it is what a name unlinked while the file is still open looks \
             like, and equally what an image of a running or uncleanly shut down machine looks \
             like when the $MFT write landed and the directory index write did not. Which of \
             those it is cannot be told from a cold image."
        ),
    ))
}

fn recorded_size(candidate: &Candidate) -> Option<u64> {
    candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::FileExists { size, .. } => Some(*size),
        _ => None,
    })
}

fn from_quarantine<R: Read + Seek>(
    volume: &Volume<R>,
    store: &QuarantineStore,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let entry = store.lookup(candidate.path.as_ref()?)?;
    let relative = quarantine::resource_data_relative_path(&entry.resource_id)?;
    let path = format!("{QUARANTINE_RESOURCE_DATA}\\{relative}");

    let blob = match volume.read_capped(&path, MAX_SAMPLE_BYTES) {
        Ok(blob) => blob,
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "Defender quarantined this file as {}, but its payload could not be read \
                     from {path}: {e}",
                    entry.threat.as_deref().unwrap_or("a threat")
                ),
            })
        }
    };

    let decrypted = quarantine::decrypt(&blob);
    let Some(payload) = quarantine::extract_payload(&decrypted) else {
        return Some(Acquisition::Failed {
            reason: format!(
                "the quarantine payload at {path} decrypted but carried no complete BACKUP_DATA \
                 stream, so the file content is not recoverable from it"
            ),
        });
    };

    let computed = FileHash::compute(&payload);
    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => match entry.claimed_size {
            Some(size) if size == payload.len() as u64 => Recovery::Unverified {
                basis: format!(
                    "RC4-decrypted from the Defender quarantine store and {size} bytes long, \
                     exactly the size the quarantine entry recorded; Defender stores no digest \
                     of the content, so nothing independent confirms it"
                ),
            },
            Some(size) => {
                return Some(Acquisition::Failed {
                    reason: format!(
                        "the quarantine payload decrypted to {} bytes but the entry recorded a \
                         {size}-byte file — the store and its index disagree, so these bytes are \
                         not offered as the sample",
                        payload.len()
                    ),
                })
            }
            None => Recovery::Unverified {
                basis: "RC4-decrypted from the Defender quarantine store; the entry recorded \
                        neither a size nor a digest, so nothing confirms it"
                    .to_string(),
            },
        },
    };

    let adopt = !matches!(recovery, Recovery::Partial { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(candidate, &payload, sample_dir, ArtifactSource::DefenderQuarantine, recovery)
}

fn from_recycle_bin<R: Read + Seek>(
    volume: &Volume<R>,
    store: &RecycleBinStore,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let pointer = store.lookup(candidate.path.as_ref()?)?;

    let bytes = match volume.read_capped(&pointer.data_path, MAX_SAMPLE_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "the recycle bin stub {} says this file was deleted from {}, but its `$R` \
                     twin at {} could not be read: {e}. A recycled DIRECTORY reads this way — \
                     there is no single file to recover from one",
                    pointer.info_path, pointer.original_raw, pointer.data_path
                ),
            })
        }
    };

    if bytes.len() >= MAX_SAMPLE_BYTES {
        return Some(Acquisition::Failed {
            reason: format!(
                "this file is in the recycle bin as {}, but it is past the {} MB copy limit, so \
                 it was not copied and not hashed — a hash of the first {} MB is not this file's \
                 hash",
                pointer.data_path,
                MAX_SAMPLE_BYTES / (1024 * 1024),
                MAX_SAMPLE_BYTES / (1024 * 1024)
            ),
        });
    }

    let computed = FileHash::compute(&bytes);

    let size_disagreement = (pointer.claimed_size != bytes.len() as u64).then(|| {
        format!(
            "recovered {} bytes from {}, the recycle bin's copy of {}, but the `$I` stub {} \
             records a {}-byte file — the bin and its index disagree, so something changed after \
             the deletion and these bytes are not offered as the sample",
            bytes.len(),
            pointer.data_path,
            pointer.original_raw,
            pointer.info_path,
            pointer.claimed_size
        )
    });

    let deleted = pointer.deleted.as_deref().map(|t| format!(" on {t}")).unwrap_or_default();

    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => match size_disagreement {
            Some(detail) => Recovery::Partial { detail },
            None => Recovery::Unverified {
                basis: format!(
                    "read whole from {}, an allocated file on this volume — nothing was \
                     reconstructed and no cluster was carved, so these {} bytes are that file's \
                     own. What rests on evidence is the NAME: the `$I` stub {} says the file \
                     deleted{} was {}, and the `$R` entry beside it is its pair by the spelling \
                     of the two names. That stub is {}, and it sits in a directory the deleting \
                     user could write. Its recorded size matches what was read. No artifact \
                     recorded a hash to confirm the identity against",
                    pointer.data_path,
                    bytes.len(),
                    pointer.info_path,
                    deleted,
                    pointer.original_raw,
                    pointer.layout
                ),
            },
        },
    };

    let adopt = !matches!(recovery, Recovery::Partial { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(candidate, &bytes, sample_dir, ArtifactSource::RecycleBin, recovery)
}

fn from_carved_clusters<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let expected_name = path.file_name()?.to_string();
    let (record, sequence) = deleted_mft_record(candidate)?;

    if let Some(sequence) = sequence {
        let fate = volume.record_fate(record, sequence);
        if !matches!(fate, Fate::Free) {
            return Some(Acquisition::Failed {
                reason: format!(
                    "the change journal recorded this file's deletion at $MFT record {record}, \
                     sequence {sequence}, and since then {fate} — so the runlist that record \
                     carries now is not this file's, and carving it would offer another file's \
                     clusters under this name. Nothing was carved from it"
                ),
            });
        }
    }

    carve_from_record(volume, clusters, candidate, sample_dir, record, &expected_name)
}

fn carve_from_record<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
    record: u64,
    expected_name: &str,
) -> Option<Acquisition> {
    let Some(identity) = volume.record_identity(record) else {
        return Some(Acquisition::Failed {
            reason: format!(
                "the file is deleted and MFT record {record} could no longer be read, so its \
                 clusters could not be followed"
            ),
        });
    };
    if identity.in_use {
        return Some(Acquisition::Failed {
            reason: format!(
                "the file is deleted and MFT record {record} has since been reallocated to \
                 `{}` — its clusters now describe that file, not this one",
                identity.name
            ),
        });
    }
    if identity.name.to_lowercase() != expected_name {
        return Some(Acquisition::Failed {
            reason: format!(
                "the file is deleted and MFT record {record} now names `{}` rather than `{}`, so \
                 it is no longer the record this candidate came from",
                identity.name, expected_name
            ),
        });
    }

    if volume.is_efs_encrypted(record) {
        return Some(Acquisition::Failed {
            reason: format!(
                "MFT record {record} survives the deleted file, but it is EFS-encrypted — the \
                 clusters its runlist points at hold ciphertext, so carving them would not \
                 recover this file's bytes and their hash would not be this file's hash"
            ),
        });
    }

    let bytes = match volume.read_record_capped(record, MAX_SAMPLE_BYTES) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "MFT record {record} survives the deleted file but its $DATA is empty, so \
                     there is nothing to carve"
                ),
            })
        }
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!("the deleted file's clusters could not be read back: {e}"),
            })
        }
    };

    let runs = volume.data_runs(record);
    let allocation = clusters.allocation(volume, &runs);
    let computed = FileHash::compute(&bytes);

    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => carve_basis(record, &runs, allocation, bytes.len()),
    };

    let adopt = !matches!(recovery, Recovery::Partial { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(candidate, &bytes, sample_dir, ArtifactSource::Mft, recovery)
}

fn carve_basis(record: u64, runs: &[Run], allocation: Option<Allocation>, size: usize) -> Recovery {
    if runs.is_empty() {
        return Recovery::Unverified {
            basis: format!(
                "carved from MFT record {record}, which is still free and still names this file; \
                 the {size}-byte $DATA was resident in the record itself, so no clusters were \
                 involved and nothing could have overwritten it. No artifact recorded a hash to \
                 confirm it against"
            ),
        };
    }

    match allocation {
        Some(a) if a.reused > 0 => Recovery::Partial {
            detail: format!(
                "carved {size} bytes from MFT record {record}, but $Bitmap shows {} of its {} \
                 clusters have been reallocated since the file was deleted — that much of these \
                 bytes belongs to another file. Treat this as fragments, not as the sample",
                a.reused,
                a.total()
            ),
        },
        Some(a) if a.unknown > 0 => Recovery::Unverified {
            basis: format!(
                "carved {size} bytes from MFT record {record}, which is still free and still \
                 names this file; {} of its {} clusters are past the end of the $Bitmap we could \
                 read, so whether they were reused is unknown. No artifact recorded a hash to \
                 confirm it against",
                a.unknown,
                a.total()
            ),
        },
        Some(a) if a.sparse == 0 => Recovery::Unverified {
            basis: format!(
                "carved {size} bytes from MFT record {record}, which is still free and still \
                 names this file, and all {} of its clusters are still marked free in $Bitmap, so \
                 nothing has overwritten them. No artifact recorded a hash to confirm it against",
                a.free
            ),
        },
        Some(a) if a.free > 0 => Recovery::Unverified {
            basis: format!(
                "carved {size} bytes from MFT record {record}, which is still free and still \
                 names this file; {} of its {} clusters are still marked free in $Bitmap, so \
                 nothing has overwritten those. The other {} are sparse — holes that were never \
                 on the disk, so $Bitmap says nothing about them and what was read back there is \
                 zeroes NTFS supplied, not the file. No artifact recorded a hash to confirm it \
                 against",
                a.free,
                a.total(),
                a.sparse
            ),
        },
        Some(a) => Recovery::Partial {
            detail: format!(
                "carved {size} bytes from MFT record {record}, but all {} of the clusters its \
                 runlist names are sparse — holes that were never on the disk. These bytes are \
                 the zeroes NTFS supplies for a hole, not the file, and $Bitmap has nothing to \
                 say about them. Treat this as nothing recovered, not as the sample",
                a.total()
            ),
        },
        None => Recovery::Unverified {
            basis: format!(
                "carved {size} bytes from MFT record {record}, which is still free and still \
                 names this file; $Bitmap could not be read, so whether the clusters were reused \
                 since the deletion is unknown, and no artifact recorded a hash to confirm it \
                 against"
            ),
        },
    }
}

fn compare_with_recorded_hash(candidate: &Candidate, computed: &FileHash) -> Option<Recovery> {
    let (source, recorded) = recorded_hash(candidate)?;
    if !recorded.agrees_with(computed) && !shares_an_algorithm(&recorded, computed) {
        return None;
    }
    if recorded.agrees_with(computed) {
        return Some(Recovery::Confirmed { against: source.label() });
    }
    Some(Recovery::Partial {
        detail: format!(
            "the recovered bytes hash to {}, but {} recorded {} for this file — so this is not \
             the file, or not all of it",
            computed.best().unwrap_or_else(|| "nothing".into()),
            source.label(),
            recorded.best().unwrap_or_else(|| "nothing".into())
        ),
    })
}

fn shares_an_algorithm(a: &FileHash, b: &FileHash) -> bool {
    (a.md5.is_some() && b.md5.is_some())
        || (a.sha1.is_some() && b.sha1.is_some())
        || (a.sha256.is_some() && b.sha256.is_some())
}

fn recorded_hash(candidate: &Candidate) -> Option<(ArtifactSource, FileHash)> {
    candidate.recorded_hash().map(|(source, hash)| (source.clone(), hash.clone()))
}

fn deleted_mft_record(candidate: &Candidate) -> Option<(u64, Option<u16>)> {
    candidate.observations.iter().find_map(|o| match &o.kind {
        ObservationKind::FileDeleted { record: Some(record), sequence, .. } => {
            Some((*record, *sequence))
        }
        _ => None,
    })
}

pub(crate) fn save(
    candidate: &Candidate,
    bytes: &[u8],
    sample_dir: &SampleDir,
    via: ArtifactSource,
    recovery: Recovery,
) -> Option<Acquisition> {
    if !sample_dir.write_out {
        return Some(Acquisition::Withheld { via, size: bytes.len() as u64, recovery });
    }
    let file_name = format!("{}.bin", candidate.id);
    let destination = sample_dir.path.join(&file_name);
    if let Err(e) = std::fs::write(&destination, bytes) {
        return Some(Acquisition::Failed {
            reason: format!("recovered {} bytes but could not write them out: {e}", bytes.len()),
        });
    }
    Some(Acquisition::Bytes {
        via,
        size: bytes.len() as u64,
        saved_as: format!("{}/{file_name}", sample_dir.relative),
        recovery,
    })
}

const MAX_SHADOW_COPIES: usize = 8;

pub struct ShadowStore<R: Read + Seek> {
    catalog: mm_raw::vss::Catalog,
    opened: Vec<OpenShadowCopy<R>>,
    refused: Vec<String>,
}

struct OpenShadowCopy<R: Read + Seek> {
    copy: mm_raw::vss::ShadowCopy,
    volume: Volume<mm_raw::vss::ShadowReader<mm_raw::SharedReader<R>>>,
    uncertain: std::sync::Arc<std::sync::atomic::AtomicU64>,
    overlays: usize,
}

impl<R: Read + Seek> ShadowStore<R> {
    #[cfg(test)]
    pub fn none() -> Self {
        ShadowStore {
            catalog: mm_raw::vss::Catalog::default(),
            opened: Vec::new(),
            refused: Vec::new(),
        }
    }

    pub fn open(volume: &Volume<R>) -> Self {
        let catalog = volume.shadow_copies();
        let length = volume.length();
        let mut opened = Vec::new();
        let mut refused = catalog.refused.clone();

        for copy in catalog.copies.iter().take(MAX_SHADOW_COPIES) {
            const VOLUME_SIZE_SLACK: u64 = 1024 * 1024;
            if copy.volume_size == 0 || copy.volume_size > length.saturating_add(VOLUME_SIZE_SLACK)
            {
                refused.push(format!(
                    "shadow copy {} describes a {}-byte volume, but this volume is {length} bytes",
                    copy.id, copy.volume_size
                ));
                continue;
            }

            let mut handle = volume.reader_handle();
            let (map, mut problems) = mm_raw::vss::read_block_map(&mut handle, copy, length);
            refused.append(&mut problems);

            if map.truncated {
                refused.push(format!(
                    "shadow copy {} was not opened: its block map exceeded the cap, and a partial \
                     map would serve today's bytes where the snapshot's belong",
                    copy.id
                ));
                continue;
            }

            let overlays = map.overlay_count();
            let reader = mm_raw::vss::ShadowReader::new(
                volume.reader_handle(),
                map,
                copy.volume_size.min(length),
            );
            let uncertain = reader.uncertainty();
            match Volume::open(reader, "shadow copy") {
                Ok(shadow) => opened.push(OpenShadowCopy {
                    copy: copy.clone(),
                    volume: shadow,
                    uncertain,
                    overlays,
                }),
                Err(e) => refused.push(format!(
                    "shadow copy {} has a block map but its filesystem would not open: {e}",
                    copy.id
                )),
            }
        }

        ShadowStore { catalog, opened, refused }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.opened.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.opened.is_empty()
    }

    #[cfg(test)]
    pub fn catalogued(&self) -> usize {
        self.catalog.copies.len()
    }

    pub fn refusals(&self) -> &[String] {
        &self.refused
    }

    pub fn coverage_line(&self) -> String {
        if self.catalog.copies.is_empty() {
            return "volume shadow copies (none on this volume — either System Restore was off, \
                    or they were deleted)"
                .to_string();
        }
        let span = match self.catalog.coverage() {
            Some((from, to)) if from == to => format!("taken {}", from.format("%Y-%m-%d %H:%M")),
            Some((from, to)) => format!(
                "covering {} to {}",
                from.format("%Y-%m-%d %H:%M"),
                to.format("%Y-%m-%d %H:%M")
            ),
            None => "undated".to_string(),
        };
        let readable = if self.opened.len() == self.catalog.copies.len() {
            String::new()
        } else {
            format!("; {} of {} readable", self.opened.len(), self.catalog.copies.len())
        };
        format!("volume shadow copies ({span}{readable})")
    }

    pub fn coverage_status(&self) -> mm_report::CoverageStatus {
        if self.catalog.copies.is_empty() {
            mm_report::CoverageStatus::Absent
        } else {
            mm_report::CoverageStatus::Read { observations: self.opened.len() }
        }
    }
}

fn from_shadow_copy<R: Read + Seek>(
    shadows: &ShadowStore<R>,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;

    let found = shadows.opened.iter().find(|shadow| shadow.volume.exists(path.key()))?;

    if found.volume.path_is_efs_encrypted(path.key()) {
        return Some(Acquisition::Failed {
            reason: format!(
                "a shadow copy taken {} still holds `{}`, but it was EFS-encrypted when the \
                 snapshot was taken, so what it holds is ciphertext",
                snapshot_label(&found.copy),
                path.raw()
            ),
        });
    }

    let before = found.uncertain.load(std::sync::atomic::Ordering::Relaxed);
    let bytes = match found.volume.read_capped(path.key(), MAX_SAMPLE_BYTES) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "a shadow copy taken {} still lists `{}`, but its bytes could not be read: {e}",
                    snapshot_label(&found.copy),
                    path.raw()
                ),
            })
        }
    };
    let touched_uncertain = found.uncertain.load(std::sync::atomic::Ordering::Relaxed) > before;

    if bytes.len() >= MAX_SAMPLE_BYTES {
        return Some(Acquisition::Failed {
            reason: format!(
                "a shadow copy taken {} holds `{}`, but it is past the {} MB copy limit, so it \
                 was not copied and not hashed",
                snapshot_label(&found.copy),
                path.raw(),
                MAX_SAMPLE_BYTES / (1024 * 1024)
            ),
        });
    }
    if bytes.is_empty() {
        return Some(Acquisition::Failed {
            reason: format!(
                "a shadow copy taken {} lists `{}` but holds no bytes for it",
                snapshot_label(&found.copy),
                path.raw()
            ),
        });
    }

    let computed = FileHash::compute(&bytes);
    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => Recovery::Unverified {
            basis: shadow_basis(&found.copy, found.overlays, touched_uncertain),
        },
    };

    let adopt = matches!(recovery, Recovery::Confirmed { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(
        candidate,
        &bytes,
        sample_dir,
        ArtifactSource::VolumeShadowCopy { snapshot: snapshot_label(&found.copy) },
        recovery,
    )
}

fn snapshot_label(copy: &mm_raw::vss::ShadowCopy) -> String {
    match copy.created {
        Some(t) => t.format("%Y-%m-%d %H:%M").to_string(),
        None => copy.id.clone(),
    }
}

fn shadow_basis(copy: &mm_raw::vss::ShadowCopy, overlays: usize, touched: bool) -> String {
    let mut basis = format!(
        "read whole through NTFS from the volume shadow copy taken {}, so nothing was \
         reconstructed and no cluster was guessed — but these are the bytes of the file that was \
         at this path in that snapshot, and nothing independent confirms it is the file the \
         artifacts name",
        snapshot_label(copy)
    );
    if touched {
        basis.push_str(&format!(
            "; part of it came from one of the {overlays} block(s) in this store carrying a \
             partial-overwrite record this reader does not apply, so those bytes may be today's \
             rather than the snapshot's"
        ));
    }
    basis
}

fn from_recorded_hash(candidate: &Candidate) -> Option<Acquisition> {
    if candidate.hash.is_empty() {
        return None;
    }

    let via = candidate
        .observations
        .iter()
        .find(|o| !o.hash.is_empty())
        .map(|o| o.source.clone())
        .or_else(|| {
            candidate
                .observations
                .iter()
                .find(|o| matches!(o.kind, ObservationKind::HashRecovered))
                .map(|o| o.source.clone())
        })?;

    Some(Acquisition::HashOnly { via })
}

#[derive(Clone, Debug, Default)]
pub struct OrphanIndex {
    unique: HashMap<Box<str>, Orphan>,
    ambiguous: HashMap<Box<str>, usize>,
}

#[derive(Clone, Debug)]
struct Orphan {
    record: u64,
    size: u64,
    deleted_at: Option<Box<str>>,
}

impl OrphanIndex {
    pub fn build(orphans: &[OrphanedDeleted]) -> Self {
        let mut counts: HashMap<Box<str>, usize> = HashMap::new();
        for o in orphans {
            *counts.entry(o.name.clone()).or_default() += 1;
        }
        let mut unique = HashMap::new();
        let mut ambiguous = HashMap::new();
        for o in orphans {
            match counts.get(&o.name).copied().unwrap_or(0) {
                0 | 1 => {
                    unique.insert(
                        o.name.clone(),
                        Orphan {
                            record: o.record,
                            size: o.size,
                            deleted_at: o
                                .deleted_at
                                .map(|t| t.format("%Y-%m-%d %H:%M:%SZ").to_string().into()),
                        },
                    );
                }
                n => {
                    ambiguous.insert(o.name.clone(), n);
                }
            }
        }
        Self { unique, ambiguous }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.unique.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.unique.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct GhostIndex {
    unique: HashMap<Box<str>, Ghost>,
    ambiguous: HashMap<Box<str>, usize>,
    scanned_bytes: u64,
    images: usize,
    refusal: Option<String>,
}

impl GhostIndex {
    pub fn build<R: Read + Seek>(volume: &Volume<R>) -> Self {
        let mut index = GhostIndex::default();
        let bytes = match volume.read_log_file(MAX_LOG_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(e) => {
                index.refusal = Some(e.to_string());
                return index;
            }
        };
        index.scanned_bytes = bytes.len() as u64;
        index.absorb(mm_raw::ghost::in_log_file(&bytes, MAX_GHOSTS));
        index
    }

    fn absorb(&mut self, ghosts: Vec<Ghost>) {
        let mut distinct: HashMap<Box<str>, Vec<Ghost>> = HashMap::new();
        for ghost in ghosts.into_iter().filter(Ghost::has_bytes) {
            self.images += 1;
            let name: Box<str> = ghost.name.to_lowercase().into();
            if !distinct.contains_key(&name) && distinct.len() >= MAX_GHOST_NAMES {
                continue;
            }
            let known = distinct.entry(name).or_default();
            if !known.iter().any(|seen| same_file(seen, &ghost)) {
                known.push(ghost);
            }
        }
        for (name, mut found) in distinct {
            match found.len() {
                0 => {}
                1 => {
                    self.unique.insert(name, found.remove(0));
                }
                n => {
                    self.ambiguous.insert(name, n);
                }
            }
        }
    }

    fn lookup(&self, name: &str) -> Option<&Ghost> {
        self.unique.get(name.to_lowercase().as_str())
    }

    fn disagreeing(&self, name: &str) -> Option<usize> {
        self.ambiguous.get(name.to_lowercase().as_str()).copied()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.unique.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.unique.is_empty()
    }

    pub fn coverage_line(&self) -> String {
        match &self.refusal {
            Some(why) => format!("$LogFile (not read: {why})"),
            None => format!(
                "$LogFile ({} MB scanned, {} record image(s), {} name(s) it alone can place)",
                self.scanned_bytes / (1024 * 1024),
                self.images,
                self.unique.len()
            ),
        }
    }

    pub fn coverage_status(&self) -> mm_report::CoverageStatus {
        match &self.refusal {
            Some(reason) => mm_report::CoverageStatus::Failed { reason: reason.clone() },
            None => mm_report::CoverageStatus::Read { observations: self.unique.len() },
        }
    }
}

fn same_file(a: &Ghost, b: &Ghost) -> bool {
    a.parent == b.parent
        && a.real_size == b.real_size
        && a.runs == b.runs
        && a.resident == b.resident
}

fn from_record_slack<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let expected_name = path.file_name()?.to_string();
    if candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })) {
        return None;
    }

    let mut records: Vec<u64> = candidate
        .observations
        .iter()
        .filter_map(|o| match &o.kind {
            ObservationKind::FileDeleted { record, .. } => *record,
            ObservationKind::FileExists { record, .. } => *record,
            _ => None,
        })
        .collect();
    records.sort_unstable();
    records.dedup();

    for record in records {
        let Some(ghost) = volume.ghost_in_record_slack(record) else { continue };
        if !ghost.name.eq_ignore_ascii_case(&expected_name) {
            continue;
        }
        let held = match volume.record_identity(record) {
            Some(identity) if identity.in_use => format!(
                "$MFT record {record} has since been handed to `{}`, which uses less of it than \
                 this file did",
                identity.name
            ),
            _ => format!("$MFT record {record} was rewritten shorter than this file left it"),
        };
        return from_ghost(volume, clusters, candidate, sample_dir, &ghost, &held);
    }
    None
}

fn from_log_file<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    ghosts: &GhostIndex,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let expected_name = path.file_name()?.to_string();
    if candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })) {
        return None;
    }

    if let Some(n) = ghosts.disagreeing(&expected_name) {
        return Some(Acquisition::Failed {
            reason: format!(
                "$LogFile holds {n} record image(s) named `{expected_name}` that describe \
                 different files — different parents, sizes or clusters. Nothing says which of \
                 them is this path's, so none of them was carved"
            ),
        });
    }

    let ghost = ghosts.lookup(&expected_name)?;
    let parent = path.parent().and_then(|parent| volume.resolve(parent));
    let placed = match parent {
        Some(record) if record == ghost.parent => format!(
            "and the directory this path names is $MFT record {record}, the same parent that \
             image records, so the name and the clusters belong to each other"
        ),
        Some(record) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "$LogFile holds a record image named `{expected_name}`, but it belongs to \
                     $MFT record {} and this path's directory is record {record} — a different \
                     file of the same name. Nothing was carved",
                    ghost.parent
                ),
            })
        }
        None => format!(
            "the directory this path names no longer resolves on this volume, so nothing \
             confirms the image found in $LogFile is THIS `{expected_name}` rather than another \
             of the same name — what places it is the name alone, and it names parent record {}",
            ghost.parent
        ),
    };

    from_ghost(volume, clusters, candidate, sample_dir, ghost, &placed)
}

fn from_ghost<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
    ghost: &Ghost,
    placed: &str,
) -> Option<Acquisition> {
    let name = ghost.name.clone();
    let mut standing = None;
    let bytes = match &ghost.resident {
        Some(resident) => resident.clone(),
        None => {
            let allocation = clusters.allocation(volume, &ghost.runs);
            match &allocation {
                Some(a) if a.reused > 0 => {
                    return Some(Acquisition::Failed {
                        reason: format!(
                            "{} names `{name}` and the {} cluster(s) it held, but $Bitmap has \
                             since given {} of them to another file. What is there now is that \
                             file's, so nothing was carved: no record binds these clusters to \
                             this name any more, and a half-overwritten image cannot be told \
                             from a whole one without a digest. {placed}",
                            ghost.found,
                            a.total(),
                            a.reused
                        ),
                    })
                }
                Some(a) if a.free == 0 => {
                    return Some(Acquisition::Failed {
                        reason: format!(
                            "{} names `{name}`, but every cluster of the runlist it carries is \
                             sparse or past the end of the $Bitmap that could be read, so there \
                             is nothing on the disk to carve. {placed}",
                            ghost.found
                        ),
                    })
                }
                Some(a) if a.unknown > 0 || a.sparse > 0 => {
                    standing = Some(format!(
                        "{} of the {} cluster(s) its runlist names are still marked free in \
                         $Bitmap, so nothing has overwritten those; the other {} are sparse \
                         holes or past the end of the $Bitmap that could be read, and what came \
                         back there is not vouched for",
                        a.free,
                        a.total(),
                        a.total() - a.free
                    ));
                }
                Some(a) => {
                    standing = Some(format!(
                        "the {} cluster(s) its runlist names are all still marked free in \
                         $Bitmap, so nothing has overwritten them",
                        a.free
                    ));
                }
                None => {
                    standing = Some(
                        "$Bitmap could not be read, so whether the clusters its runlist names \
                         were reused since the deletion is UNKNOWN"
                            .to_string(),
                    );
                }
            }
            match volume.read_run_data(&ghost.runs, ghost.real_size, MAX_SAMPLE_BYTES) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => {
                    return Some(Acquisition::Failed {
                        reason: format!(
                            "{} names `{name}` and a runlist, but reading it back produced no \
                             bytes. {placed}",
                            ghost.found
                        ),
                    })
                }
                Err(e) => {
                    return Some(Acquisition::Failed {
                        reason: format!(
                            "{} names `{name}` and the clusters it held, but they could not be \
                             read back: {e}. {placed}",
                            ghost.found
                        ),
                    })
                }
            }
        }
    };

    let computed = FileHash::compute(&bytes);
    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => Recovery::Unverified { basis: ghost_basis(ghost, &bytes, placed, standing) },
    };

    let adopt = !matches!(recovery, Recovery::Partial { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(candidate, &bytes, sample_dir, ArtifactSource::Mft, recovery)
}

fn ghost_basis(ghost: &Ghost, bytes: &[u8], placed: &str, standing: Option<String>) -> String {
    let held = match standing {
        Some(clusters) => format!("{clusters}, and {} byte(s) were read from them", bytes.len()),
        None => format!(
            "the {} byte(s) were resident IN that record, so they are the file itself and no \
             cluster was involved — nothing could have overwritten them",
            bytes.len()
        ),
    };
    format!(
        "carved from a $FILE_NAME and $DATA pair that outlived their own $MFT record: {}. That \
         is a record NTFS no longer accounts for — no directory entry and no live record points \
         at it, and this run did not find one — so what binds these bytes to this path is the \
         name written in those leftover attributes and nothing else. {held}. {placed}. The size \
         they record is {}. No artifact recorded a hash to confirm any of it",
        ghost.found, ghost.real_size
    )
}

fn from_index_slack<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    slack: &RecoveredNames,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let expected_name = path.file_name()?.to_string();
    let found = slack.get(path)?.clone();

    if candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })) {
        return None;
    }
    if deleted_mft_record(candidate).is_some() {
        return None;
    }

    let record = found.record;
    match &found.fate {
        Fate::Free => {}
        Fate::StillThere => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "`{expected_name}` was recovered from the {} of its parent directory, naming \
                     $MFT record {record} at sequence {}. That record is IN USE under the same \
                     sequence, so it is still this name's record and the file is not established \
                     to be deleted at all — the entry is a stale copy a rename or a rebalanced \
                     B-tree left behind. Nothing was carved: reading a live file's clusters and \
                     offering them as a deleted sample would be a claim nobody made",
                    found.found_in, found.sequence
                ),
            });
        }
        Fate::Reallocated { sequence, to } => {
            let now = match to {
                Some(name) => format!("`{name}`"),
                None => "a file whose name the record would not give up".to_string(),
            };
            return Some(Acquisition::Failed {
                reason: format!(
                    "`{expected_name}` was recovered from the {} of its parent directory — {} \
                     bytes, $MFT record {record} at sequence {}. Windows has since handed that \
                     record to {now} (sequence {sequence}), so its runlist now describes that \
                     file and nothing on this volume points at these bytes any more. This is a \
                     stated reallocation and not a failure to look{}",
                    found.found_in,
                    found.real_size,
                    found.sequence,
                    found.stamps()
                ),
            });
        }
        Fate::FreedAgain { sequence } => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "`{expected_name}` was recovered from the {} of its parent directory, naming \
                     $MFT record {record} at sequence {}. That record is free but carries \
                     sequence {sequence}: it was reallocated to another file after this name and \
                     freed again, so its runlist is the LAST file's and not this one's. Nothing \
                     was carved",
                    found.found_in, found.sequence
                ),
            });
        }
        Fate::Unknown => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "`{expected_name}` was recovered from the {} of its parent directory, naming \
                     $MFT record {record}. That record could not be read, does not parse, or \
                     holds another file's spilled attributes, so what became of it is UNKNOWN and \
                     nothing was carved",
                    found.found_in
                ),
            });
        }
    }

    let acquisition =
        carve_from_record(volume, clusters, candidate, sample_dir, record, &expected_name)?;

    let Acquisition::Bytes { via, size, saved_as, recovery } = acquisition else {
        return Some(acquisition);
    };
    if found.real_size != 0 && found.real_size != size {
        return Some(Acquisition::Bytes {
            via,
            size,
            saved_as,
            recovery: Recovery::Partial {
                detail: format!(
                    "carved {size} bytes from MFT record {record}, but the entry this file's \
                     parent directory still holds for it records a length of {} bytes. The \
                     directory and the record disagree about the size of the same file, so these \
                     bytes are not offered as the sample",
                    found.real_size
                ),
            },
        });
    }
    Some(Acquisition::Bytes { via, size, saved_as, recovery })
}

fn from_orphaned_record<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    orphans: &OrphanIndex,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Option<Acquisition> {
    let path = candidate.path.as_ref()?;
    let name = path.file_name()?.to_string();
    if candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })) {
        return None;
    }
    if deleted_mft_record(candidate).is_some() {
        return None;
    }

    if let Some(n) = orphans.ambiguous.get(name.as_str()) {
        return Some(Acquisition::Failed {
            reason: format!(
                "the file is gone and its directory is gone with it, so nothing on this volume \
                 says which record was this file's. {n} deleted $MFT records are named `{name}` \
                 and none of them can be placed at a path — carving one would be a guess, so \
                 none was carved. `malmathic diag mft --record N` will read any of them"
            ),
        });
    }
    let orphan = orphans.unique.get(name.as_str())?.clone();
    let record = orphan.record;

    let Some(identity) = volume.record_identity(record) else {
        return Some(Acquisition::Failed {
            reason: format!(
                "a deleted $MFT record named `{name}` was found at {record} but could no longer \
                 be read, so its clusters could not be followed"
            ),
        });
    };
    if identity.in_use {
        return Some(Acquisition::Failed {
            reason: format!(
                "the deleted record named `{name}` at {record} has since been reallocated to \
                 `{}`, so its clusters now describe that file and not this one",
                identity.name
            ),
        });
    }
    if identity.name.to_lowercase() != name {
        return Some(Acquisition::Failed {
            reason: format!(
                "$MFT record {record} now names `{}` rather than `{name}`, so it is no longer \
                 the record this name came from",
                identity.name
            ),
        });
    }

    let bytes = match volume.read_record_capped(record, MAX_SAMPLE_BYTES) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "the deleted record named `{name}` at {record} survives but its $DATA is \
                     empty, so there is nothing to carve"
                ),
            })
        }
        Err(e) => {
            return Some(Acquisition::Failed {
                reason: format!(
                    "the deleted record named `{name}` at {record} could not be read back: {e}"
                ),
            })
        }
    };

    let runs = volume.data_runs(record);
    let allocation = clusters.allocation(volume, &runs);
    let computed = FileHash::compute(&bytes);

    let when = match &orphan.deleted_at {
        Some(t) => format!(
            " The record's own $SI $MFT-modified time is {t}; freeing a record is a write to it, \
             so for a free record that is the closest thing to a deletion time this volume \
             holds. It says when the RECORD was last written, which is not by itself a claim \
             about who deleted the file or when they meant to."
        ),
        None => String::new(),
    };

    let recovery = match compare_with_recorded_hash(candidate, &computed) {
        Some(verdict) => verdict,
        None => Recovery::Unverified {
            basis: format!(
                "carved from $MFT record {record}, which is free and names `{name}`. THE \
                 DIRECTORY THIS RECORD WAS IN IS UNKNOWN: its parent reference names a record \
                 that has since been handed to something else, which is what a deleted directory \
                 leaves behind. It is the only deleted record on this volume with that name, and \
                 that is the whole of the reason to think these are the right bytes — no artifact \
                 recorded a hash to check it against. {}{}",
                match allocation {
                    Some(a) if a.reused > 0 => format!(
                        "$Bitmap also shows {} of its {} clusters reallocated since, so that much \
                         of this belongs to another file again",
                        a.reused,
                        a.total()
                    ),
                    _ if bytes.len() as u64 == orphan.size => format!(
                        "{} bytes were read, which is the size the record declares",
                        bytes.len()
                    ),
                    _ => format!(
                        "{} bytes were read; the record declares {}",
                        bytes.len(),
                        orphan.size
                    ),
                },
                when
            ),
        },
    };

    let adopt = matches!(recovery, Recovery::Confirmed { .. });
    candidate.record_acquired_hash(&computed, adopt);

    save(candidate, &bytes, sample_dir, ArtifactSource::Mft, recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{CandidateId, NormalizedPath, Observation};

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn candidate_with_hash(source: ArtifactSource) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\gone.exe");
        c.observe(
            Observation::about_path(
                source,
                NormalizedPath::parse("C:\\Users\\bob\\gone.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_amcache_file_id(&format!("0000{}", "ab".repeat(20))).unwrap(),
            ),
        );
        c
    }

    #[test]
    fn a_deleted_file_is_still_identified_by_its_recorded_hash() {
        let c = candidate_with_hash(ArtifactSource::Amcache);
        match from_recorded_hash(&c) {
            Some(Acquisition::HashOnly { via }) => assert_eq!(via, ArtifactSource::Amcache),
            other => panic!("expected a hash-only acquisition, got {other:?}"),
        }
    }

    #[test]
    fn provenance_points_at_the_artifact_that_carried_the_hash() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        let path = NormalizedPath::parse("C:\\Users\\bob\\gone.exe").unwrap();
        c.observe(Observation::about_path(
            ArtifactSource::ShimCache,
            path.clone(),
            ObservationKind::Executed { when: None, run_count: None },
        ));
        c.observe(
            Observation::about_path(ArtifactSource::Amcache, path, ObservationKind::HashRecovered)
                .with_hash(FileHash::compute(b"payload")),
        );

        match from_recorded_hash(&c) {
            Some(Acquisition::HashOnly { via }) => assert_eq!(via, ArtifactSource::Amcache),
            other => panic!("expected Amcache provenance, got {other:?}"),
        }
    }

    #[test]
    fn a_candidate_with_no_hash_yields_nothing_from_that_route() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\gone.exe");
        c.observe(Observation::about_path(
            ArtifactSource::ShimCache,
            NormalizedPath::parse("C:\\Users\\bob\\gone.exe").unwrap(),
            ObservationKind::Executed { when: None, run_count: None },
        ));
        assert!(from_recorded_hash(&c).is_none());
    }

    #[test]
    fn failure_explains_itself() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse("C:\\Users\\bob\\gone.exe");
        let reason = match from_recorded_hash(&c) {
            None => "the file is gone and no artifact recorded its hash",
            _ => unreachable!(),
        };
        assert!(reason.contains("no artifact recorded its hash"));
    }

    #[test]
    fn the_mft_record_of_a_deleted_file_reaches_the_carver() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\Users\\bob\\gone.exe"),
            ObservationKind::FileDeleted { when: None, record: Some(84_215), sequence: None },
        ));
        assert_eq!(deleted_mft_record(&c), Some((84_215, None)));
    }

    #[test]
    fn a_deletion_with_no_record_offers_nothing_to_carve() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path("C:\\Users\\bob\\gone.exe"),
            ObservationKind::FileDeleted { when: None, record: None, sequence: None },
        ));
        assert_eq!(deleted_mft_record(&c), None);

        let mut executed = Candidate::new(CandidateId(2), -9.2);
        executed.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path("C:\\Users\\bob\\gone.exe"),
            ObservationKind::Executed { when: None, run_count: None },
        ));
        assert_eq!(deleted_mft_record(&executed), None);
    }

    fn with_recorded(source: ArtifactSource, hash: FileHash) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.observe(
            Observation::about_path(
                source,
                path("C:\\Users\\bob\\gone.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(hash),
        );
        c
    }

    #[test]
    fn recovered_bytes_matching_a_recorded_hash_are_confirmed() {
        let sample = b"MZ\x90\x00the malware";
        let recorded = FileHash::from_sha1_hex(&FileHash::compute(sample).sha1_hex().unwrap());
        let c = with_recorded(ArtifactSource::Amcache, recorded.unwrap());

        match compare_with_recorded_hash(&c, &FileHash::compute(sample)) {
            Some(Recovery::Confirmed { against }) => assert_eq!(against, "Amcache"),
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn recovered_bytes_contradicting_a_recorded_hash_are_partial() {
        let recorded = FileHash::compute(b"the real malware");
        let c = with_recorded(ArtifactSource::Amcache, recorded);

        match compare_with_recorded_hash(&c, &FileHash::compute(b"half of it, overwritten")) {
            Some(Recovery::Partial { detail }) => {
                assert!(detail.contains("Amcache"), "{detail}");
                assert!(detail.contains("not the file"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn hashes_with_no_shared_algorithm_decide_nothing() {
        let md5_only = FileHash::from_md5_hex("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        let c = with_recorded(ArtifactSource::DefenderLog { event_id: 1117 }, md5_only);
        let sha1_only =
            FileHash::from_sha1_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert!(compare_with_recorded_hash(&c, &sha1_only).is_none());
    }

    #[test]
    fn a_candidate_nothing_hashed_leaves_the_comparison_undecided() {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\Users\\bob\\gone.exe"),
            ObservationKind::FileDeleted { when: None, record: Some(9), sequence: None },
        ));
        assert!(compare_with_recorded_hash(&c, &FileHash::compute(b"x")).is_none());
    }

    #[test]
    fn only_intact_and_confirmed_recoveries_are_trustworthy() {
        assert!(Recovery::Intact.is_trustworthy());
        assert!(Recovery::Confirmed { against: "Amcache".into() }.is_trustworthy());
        assert!(!Recovery::Unverified { basis: "clusters still free".into() }.is_trustworthy());
        assert!(!Recovery::Partial { detail: "overwritten".into() }.is_trustworthy());
    }

    fn runs(spec: &[(u64, Option<u64>)]) -> Vec<Run> {
        spec.iter().map(|(length, lcn)| Run { length: *length, lcn: *lcn }).collect()
    }

    #[test]
    fn a_resident_data_carve_says_no_clusters_were_involved() {
        match carve_basis(42, &[], None, 300) {
            Recovery::Unverified { basis } => {
                assert!(basis.contains("resident"), "{basis}");
                assert!(basis.contains("no clusters"), "{basis}");
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn untouched_clusters_are_reported_as_untouched() {
        let allocation = Allocation { free: 12, ..Default::default() };
        match carve_basis(42, &runs(&[(12, Some(1000))]), Some(allocation), 48_000) {
            Recovery::Unverified { basis } => {
                assert!(basis.contains("still marked free"), "{basis}")
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn reallocated_clusters_downgrade_the_carve_to_partial() {
        let allocation = Allocation { free: 8, reused: 4, ..Default::default() };
        match carve_basis(42, &runs(&[(12, Some(1000))]), Some(allocation), 48_000) {
            Recovery::Partial { detail } => {
                assert!(detail.contains("4 of its 12 clusters"), "{detail}");
                assert!(detail.contains("fragments"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_bitmap_is_reported_as_unknown_rather_than_clean() {
        match carve_basis(42, &runs(&[(12, Some(1000))]), None, 48_000) {
            Recovery::Unverified { basis } => {
                assert!(basis.contains("$Bitmap could not be read"), "{basis}");
                assert!(basis.contains("unknown"), "{basis}");
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn clusters_past_the_end_of_the_bitmap_are_unknown_not_free() {
        let allocation = Allocation { free: 2, unknown: 10, ..Default::default() };
        match carve_basis(42, &runs(&[(12, Some(1000))]), Some(allocation), 48_000) {
            Recovery::Unverified { basis } => assert!(basis.contains("10 of its 12"), "{basis}"),
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn sparse_runs_are_not_counted_among_the_clusters_bitmap_vouches_for() {
        let allocation = Allocation { free: 4, sparse: 8, ..Default::default() };
        match carve_basis(42, &runs(&[(4, Some(1000)), (8, None)]), Some(allocation), 48_000) {
            Recovery::Unverified { basis } => {
                assert!(basis.contains("4 of its 12 clusters"), "{basis}");
                assert!(basis.contains("sparse"), "{basis}");
                assert!(
                    !basis.contains("all 12"),
                    "$Bitmap was made to vouch for eight clusters it never saw: {basis}"
                );
            }
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn a_runlist_of_nothing_but_holes_is_not_an_intact_carve() {
        let allocation = Allocation { sparse: 12, ..Default::default() };
        match carve_basis(42, &runs(&[(12, None)]), Some(allocation), 48_000) {
            Recovery::Partial { detail } => {
                assert!(detail.contains("sparse"), "{detail}");
                assert!(detail.contains("nothing recovered"), "{detail}");
                assert!(!detail.contains("still marked free"), "{detail}");
            }
            other => panic!("zeroes from holes were reported as a carve: {other:?}"),
        }
    }

    #[test]
    fn a_bitmap_that_says_the_boot_sector_is_free_is_not_a_bitmap() {
        assert!(!bitmap_is_credible(&[0u8; 4096]), "a buffer of zeroes was taken for $Bitmap");
        assert!(!bitmap_is_credible(&[]), "an empty buffer was taken for $Bitmap");
        assert!(bitmap_is_credible(&[0b0000_0001u8, 0, 0, 0]), "a real map was refused");
    }

    #[test]
    fn cluster_bits_are_read_least_significant_first() {
        let bits = [0b0000_0101u8, 0b1000_0000u8];
        assert_eq!(bit(&bits, 0), Some(true));
        assert_eq!(bit(&bits, 1), Some(false));
        assert_eq!(bit(&bits, 2), Some(true));
        assert_eq!(bit(&bits, 7), Some(false));
        assert_eq!(bit(&bits, 15), Some(true));
        assert_eq!(bit(&bits, 16), None);
        assert_eq!(bit(&bits, u64::MAX), None);
    }

    fn quarantined(path_str: &str, resource_id: &str, size: Option<u64>) -> QuarantinedFile {
        QuarantinedFile {
            path: path(path_str),
            resource_id: resource_id.to_string(),
            threat: Some("Trojan:Win32/Wacatac.B!ml".into()),
            claimed_size: size,
        }
    }

    #[test]
    fn the_quarantine_store_finds_a_file_by_its_original_path() {
        let mut store = QuarantineStore::new();
        store.add(vec![quarantined(
            "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe",
            &"A".repeat(40),
            Some(4096),
        )]);
        assert_eq!(store.len(), 1);
        assert!(store.lookup(&path("C:\\Users\\BOB\\appdata\\local\\temp\\Dropper.EXE")).is_some());
        assert!(store.lookup(&path("C:\\Users\\bob\\other.exe")).is_none());
    }

    #[test]
    fn a_repeated_quarantine_of_one_path_resolves_deterministically() {
        let mut store = QuarantineStore::new();
        store.add(vec![
            quarantined("C:\\x.exe", &"A".repeat(40), Some(1)),
            quarantined("C:\\x.exe", &"B".repeat(40), Some(2)),
        ]);
        assert_eq!(store.len(), 1);
        assert_eq!(store.lookup(&path("C:\\x.exe")).unwrap().claimed_size, Some(1));
    }

    use crate::testimage::{Builder, Presence, ROOT_RECORD};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn sample_bytes() -> Vec<u8> {
        let mut bytes = b"MZ\x90\x00this is the malware, byte for byte".to_vec();
        bytes.extend((0..=255u8).cycle().take(crate::testimage::CLUSTER * 3 + 41));
        bytes
    }

    pub(super) fn case_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "malmathic-acquire-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a case directory");
        dir
    }

    fn case_sample_dir() -> SampleDir {
        SampleDir { path: case_dir(), relative: "sample", write_out: true }
    }

    fn withholding_sample_dir() -> SampleDir {
        SampleDir { path: case_dir(), relative: "sample", write_out: false }
    }

    #[test]
    fn a_runlist_that_reaches_past_the_disk_is_counted_rather_than_walked() {
        let mut builder = Builder::new();
        builder.file(ROOT_RECORD, "dropper.exe", b"MZ", Presence::Live);
        let volume = builder.open();

        let mut clusters = ClusterMap::new();
        let described = (clusters.bits(&volume).expect("a bitmap").len() as u64) * 8;

        let started = std::time::Instant::now();
        let hostile = [Run { lcn: Some(1), length: u64::MAX }];
        let seen = clusters.allocation(&volume, &hostile).expect("the bitmap was read");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a runlist declares its own length, so walking it cluster by cluster lets the \
             volume being triaged decide how long this run takes"
        );
        assert_eq!(seen.total(), u64::MAX, "every declared cluster is still accounted for");
        assert_eq!(
            seen.unknown,
            u64::MAX - (described - 1),
            "everything past the bitmap is unknown, which is what the walk used to conclude"
        );

        let honest = [Run { lcn: Some(1), length: 2 }];
        let counted = clusters.allocation(&volume, &honest).expect("the bitmap was read");
        assert_eq!(counted.total(), 2, "an ordinary runlist is unaffected");
        assert_eq!(counted.unknown, 0);
    }

    #[test]
    fn withholding_writes_no_file_and_loses_no_evidence() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        builder.file(ROOT_RECORD, "dropper.exe", &sample, Presence::Live);
        let volume = builder.open();

        let recorded = FileHash::compute(&sample);
        let recorded_sha1 = recorded.sha1_hex().expect("a sha1");

        let kept = case_sample_dir();
        let mut a = candidate_for(r"C:\dropper.exe");
        a.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\dropper.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&recorded_sha1).unwrap()),
        );
        let with = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut a,
            &kept,
        );

        let held = withholding_sample_dir();
        let mut b = candidate_for(r"C:\dropper.exe");
        b.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\dropper.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&recorded_sha1).unwrap()),
        );
        let without = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut b,
            &held,
        );

        assert_eq!(saved_bytes(&with, &kept.path), sample);

        match (&with, &without) {
            (
                Acquisition::Bytes { via: v1, size: s1, recovery: r1, .. },
                Acquisition::Withheld { via: v2, size: s2, recovery: r2 },
            ) => {
                assert_eq!(v1, v2, "the same artifact supplied the bytes");
                assert_eq!(s1, s2, "the same number of bytes was read");
                assert_eq!(r1, r2, "the same recovery, so the same caveat or none");
            }
            other => panic!("expected Bytes then Withheld, got {other:?}"),
        }

        assert_eq!(b.hash.sha256_hex(), FileHash::compute(&sample).sha256_hex());
        assert_eq!(a.hash.sha256_hex(), b.hash.sha256_hex());
        assert_eq!(
            a.acquired_hash.as_ref().and_then(|h| h.sha256_hex()),
            b.acquired_hash.as_ref().and_then(|h| h.sha256_hex()),
        );

        let left: Vec<_> = std::fs::read_dir(&held.path)
            .expect("the case directory")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "--no-samples wrote {left:?} into the case directory");
    }

    fn candidate_for(path_str: &str) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse(path_str);
        c
    }

    fn deleted_candidate(path_str: &str, record: u64) -> Candidate {
        let mut c = candidate_for(path_str);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(path_str),
            ObservationKind::FileDeleted { when: None, record: Some(record), sequence: None },
        ));
        c
    }

    fn live_candidate(path_str: &str, record: u64) -> Candidate {
        let mut c = candidate_for(path_str);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(path_str),
            ObservationKind::FileExists {
                size: 0,
                created: None,
                modified: None,
                mft_modified: None,
                record: Some(record),
            },
        ));
        c
    }

    fn run_chain(
        volume: &Volume<impl Read + Seek>,
        c: &mut Candidate,
        out: &SampleDir,
    ) -> Acquisition {
        acquire(
            volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            c,
            out,
        )
    }

    #[test]
    fn a_file_whose_name_is_not_in_its_directory_is_still_read_from_its_record() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\Alice\\Desktop");
        let record = builder.file(dir, "cryptor.exe", &sample, Presence::Live);
        builder.delete_index_entry(dir, "cryptor.exe");
        let volume = builder.open();

        assert!(
            !volume.exists("\\Users\\Alice\\Desktop\\cryptor.exe"),
            "the fixture must not resolve, or it tests nothing"
        );
        assert!(volume.record_identity(record).is_some_and(|i| i.in_use));

        let out = case_sample_dir();
        let mut candidate = live_candidate("C:\\Users\\Alice\\Desktop\\cryptor.exe", record);
        let acquisition = run_chain(&volume, &mut candidate, &out);

        match &acquisition {
            Acquisition::Bytes {
                via, recovery: Recovery::UnlinkedButPresent { detail }, ..
            } => {
                assert_eq!(*via, ArtifactSource::Mft);
                assert!(detail.contains(&format!("$MFT record {record}")), "{detail}");
                assert!(detail.contains("NOT in the index"), "{detail}");
                assert!(detail.contains("marks every cluster"), "{detail}");
            }
            other => panic!("expected bytes off the unlinked record, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
        assert!(acquisition_recovery(&acquisition).is_trustworthy());
    }

    fn acquisition_recovery(a: &Acquisition) -> Recovery {
        match a {
            Acquisition::Bytes { recovery, .. } | Acquisition::Withheld { recovery, .. } => {
                recovery.clone()
            }
            other => panic!("no recovery on {other:?}"),
        }
    }

    #[test]
    fn a_record_reallocated_since_the_walk_is_not_read_under_the_old_name() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\Alice\\Desktop");
        let record =
            builder.file(dir, "cryptor.exe", &sample, Presence::RecordReallocatedTo("notes.txt"));
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = live_candidate("C:\\Users\\Alice\\Desktop\\cryptor.exe", record);
        let acquisition = run_chain(&volume, &mut candidate, &out);

        match &acquisition {
            Acquisition::Failed { reason } => {
                assert!(reason.contains(&format!("record {record}")), "{reason}");
                assert!(reason.contains("no longer carries this file's name"), "{reason}");
                assert!(!reason.contains("the file is gone"), "{reason}");
                assert!(reason.contains("UNKNOWN"), "{reason}");
            }
            other => panic!("a reallocated record was read anyway: {other:?}"),
        }
    }

    #[test]
    fn a_file_whose_path_resolves_is_still_plain_intact() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\Alice\\Desktop");
        let record = builder.file(dir, "cryptor.exe", &sample, Presence::Live);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = live_candidate("C:\\Users\\Alice\\Desktop\\cryptor.exe", record);
        let acquisition = run_chain(&volume, &mut candidate, &out);

        assert!(matches!(acquisition_recovery(&acquisition), Recovery::Intact));
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
    }

    #[test]
    fn a_candidate_with_no_record_still_says_the_file_is_not_on_this_volume() {
        let mut builder = Builder::new();
        builder.directories(ROOT_RECORD, "Users\\Alice\\Desktop");
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = candidate_for("C:\\Users\\Alice\\Desktop\\never-existed.exe");
        let acquisition = run_chain(&volume, &mut candidate, &out);

        match &acquisition {
            Acquisition::Failed { reason } => {
                assert!(reason.contains("no $MFT record was read for this path"), "{reason}");
                assert!(reason.contains("not on this volume under this name"), "{reason}");
            }
            other => panic!("expected a clean absence, got {other:?}"),
        }
    }

    #[test]
    fn absence_is_never_claimed_for_a_candidate_with_a_live_record() {
        let sample = sample_bytes();
        for unlink in [false, true] {
            let mut builder = Builder::new();
            let dir = builder.directories(ROOT_RECORD, "Users\\Alice\\Desktop");
            let record = builder.file(dir, "cryptor.exe", &sample, Presence::Live);
            if unlink {
                builder.delete_index_entry(dir, "cryptor.exe");
            }
            let volume = builder.open();

            let out = case_sample_dir();
            let mut candidate = live_candidate("C:\\Users\\Alice\\Desktop\\cryptor.exe", record);
            let acquisition = run_chain(&volume, &mut candidate, &out);

            if let Acquisition::Failed { reason } = &acquisition {
                assert!(
                    !reason.contains("the file is gone"),
                    "unlink={unlink}: a live record was reported as an absent file: {reason}"
                );
            }
        }
    }

    fn saved_bytes(acquisition: &Acquisition, dir: &std::path::Path) -> Vec<u8> {
        match acquisition {
            Acquisition::Bytes { saved_as, .. } => {
                std::fs::read(dir.join(saved_as.replace("sample/", ""))).expect("the saved sample")
            }
            other => panic!("expected recovered bytes, got {other:?}"),
        }
    }

    #[test]
    fn a_deleted_file_is_carved_back_byte_for_byte() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
        let record = builder.file(dir, "dropper.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate =
            deleted_candidate("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe", record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Bytes { via, size, recovery, .. } => {
                assert_eq!(*via, ArtifactSource::Mft);
                assert_eq!(*size, sample.len() as u64);
                match recovery {
                    Recovery::Unverified { basis } => {
                        assert!(basis.contains("still marked free"), "{basis}");
                        assert!(basis.contains("No artifact recorded a hash"), "{basis}");
                    }
                    other => panic!("expected Unverified, got {other:?}"),
                }
            }
            other => panic!("expected recovered bytes, got {other:?}"),
        }
        assert_eq!(
            saved_bytes(&acquisition, &out.path),
            sample,
            "the carved bytes are not the file"
        );
        assert_eq!(candidate.hash.sha256_hex(), FileHash::compute(&sample).sha256_hex());
    }

    #[test]
    fn a_compact_os_compressed_file_is_acquired_as_its_real_bytes() {
        let sample = sample_bytes();
        let chunk = 4096usize;
        let mut stream = Vec::new();
        for i in 1..sample.len().div_ceil(chunk) {
            stream.extend_from_slice(&((i * chunk) as u32).to_le_bytes());
        }
        stream.extend_from_slice(&sample);

        let mut builder = Builder::new();
        builder.compact_os_file(
            ROOT_RECORD,
            "packed.exe",
            sample.len() as u64,
            mm_raw::wof::ALGORITHM_XPRESS4K,
            &stream,
        );
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = candidate_for(r"C:\packed.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        assert_eq!(
            saved_bytes(&acquisition, &out.path),
            sample,
            "the analyst was handed the wrong bytes"
        );
        assert_eq!(candidate.hash.sha256_hex(), FileHash::compute(&sample).sha256_hex());
        assert_ne!(
            candidate.hash.sha256_hex(),
            FileHash::compute(&vec![0u8; sample.len()]).sha256_hex()
        );
    }

    #[test]
    fn a_compact_os_file_whose_reparse_point_spilled_is_not_acquired_as_nulls() {
        let sample = sample_bytes();
        let chunk = 4096usize;
        let mut stream = Vec::new();
        for i in 1..sample.len().div_ceil(chunk) {
            stream.extend_from_slice(&((i * chunk) as u32).to_le_bytes());
        }
        stream.extend_from_slice(&sample);

        let mut builder = Builder::new();
        let record = builder.compact_os_file(
            ROOT_RECORD,
            "packed.exe",
            sample.len() as u64,
            mm_raw::wof::ALGORITHM_XPRESS4K,
            &stream,
        );
        builder.spill_reparse_point(record);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = candidate_for(r"C:\packed.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        let nulls = FileHash::compute(&vec![0u8; sample.len()]);
        assert_ne!(
            candidate.hash.sha256_hex(),
            nulls.sha256_hex(),
            "the report would have printed the SHA-256 of a run of zeroes as the sample's hash"
        );
        assert_eq!(
            saved_bytes(&acquisition, &out.path),
            sample,
            "the analyst was handed the wrong bytes"
        );
        assert_eq!(candidate.hash.sha256_hex(), FileHash::compute(&sample).sha256_hex());
        assert!(
            matches!(acquisition, Acquisition::Bytes { recovery: Recovery::Intact, .. }),
            "{acquisition:?}"
        );
    }

    #[test]
    fn a_compact_os_file_whose_length_is_unknown_is_never_handed_over_as_intact() {
        let sample = sample_bytes();
        let chunk = 4096usize;
        let mut stream = Vec::new();
        for i in 1..sample.len().div_ceil(chunk) {
            stream.extend_from_slice(&((i * chunk) as u32).to_le_bytes());
        }
        stream.extend_from_slice(&sample);

        let mut builder = Builder::new();
        let packed = builder.compact_os_file(
            ROOT_RECORD,
            "packed.exe",
            0,
            mm_raw::wof::ALGORITHM_XPRESS4K,
            &stream,
        );
        let decoy = builder.compact_os_file(
            ROOT_RECORD,
            "decoy.exe",
            sample.len() as u64,
            mm_raw::wof::ALGORITHM_XPRESS4K,
            &stream,
        );
        builder.set_file_name_size(packed, 0);
        let volume = builder.open();
        let _ = decoy;

        let out = case_sample_dir();
        let mut candidate = candidate_for(r"C:\packed.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match acquisition {
            Acquisition::Failed { reason } => {
                assert!(mm_raw::wof::describes_a_compact_os_failure(&reason), "{reason}");
            }
            other => panic!("bytes nobody established were handed over: {other:?}"),
        }
        assert!(candidate.hash.sha256.is_none(), "a hash of bytes that were never read");
    }

    #[test]
    fn a_compact_os_file_whose_backing_was_refused_is_never_handed_over_as_intact() {
        let sample = sample_bytes();
        let chunk = 4096usize;
        let mut stream = Vec::new();
        for i in 1..sample.len().div_ceil(chunk) {
            stream.extend_from_slice(&((i * chunk) as u32).to_le_bytes());
        }
        stream.extend_from_slice(&sample);

        let mut builder = Builder::new();
        let packed = builder.compact_os_file(
            ROOT_RECORD,
            "packed.exe",
            sample.len() as u64,
            mm_raw::wof::ALGORITHM_XPRESS4K,
            &stream,
        );
        let decoy = builder.compact_os_file(
            ROOT_RECORD,
            "decoy.exe",
            sample.len() as u64,
            mm_raw::wof::ALGORITHM_LZX,
            &stream,
        );
        builder.spill_reparse_point(packed);
        builder.misdirect_spilled_attributes(packed, decoy);
        let volume = builder.open();

        let nulls = volume.fs().read_data_by_record(packed, None, u64::MAX).unwrap();
        assert_eq!(nulls.len(), sample.len());
        assert!(nulls.iter().all(|&b| b == 0));

        let out = case_sample_dir();
        let mut candidate = candidate_for(r"C:\packed.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match acquisition {
            Acquisition::Failed { reason } => {
                assert!(mm_raw::describes_an_unaccounted_attribute_list(&reason), "{reason}")
            }
            other => panic!("zeroes nobody established were handed over: {other:?}"),
        }
        assert!(candidate.hash.sha256.is_none(), "a hash of nulls entered the identity");
    }

    #[test]
    fn a_deleted_file_small_enough_to_live_in_its_record_is_carved_from_the_record() {
        let script = b"powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA";
        let mut builder = Builder::new();
        let record = builder.resident_file(ROOT_RECORD, "stage1.bat", script, Presence::Deleted);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = deleted_candidate("C:\\stage1.bat", record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Unverified { basis }, .. } => {
                assert!(basis.contains("resident in the record itself"), "{basis}");
                assert!(basis.contains("no clusters were involved"), "{basis}");
            }
            other => panic!("expected an Unverified resident carve, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), script);
    }

    #[test]
    fn a_deleted_file_with_a_non_english_name_is_still_carved() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Пользователи");
        let record = builder.file(dir, "Отчёт.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = deleted_candidate("C:\\Пользователи\\Отчёт.exe", record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Bytes { via, .. } => assert_eq!(*via, ArtifactSource::Mft),
            other => panic!("the carve was refused on a non-English name: {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
    }

    #[test]
    fn a_carve_an_independent_hash_confirms_says_so() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let record = builder.file(ROOT_RECORD, "gone.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let mut candidate = deleted_candidate("C:\\gone.exe", record);
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\gone.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_sha1_hex(&FileHash::compute(&sample).sha1_hex().unwrap()).unwrap(),
            ),
        );

        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Confirmed { against }, .. } => {
                assert_eq!(against, "Amcache")
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn a_carve_an_independent_hash_contradicts_is_partial_and_does_not_claim_the_identity() {
        let mut builder = Builder::new();
        let record =
            builder.file(ROOT_RECORD, "gone.exe", b"overwritten rubbish", Presence::Deleted);
        let volume = builder.open();

        let real_sha1 = FileHash::compute(b"the actual malware").sha1_hex().unwrap();
        let mut candidate = deleted_candidate("C:\\gone.exe", record);
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\gone.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&real_sha1).unwrap()),
        );

        let out = case_sample_dir();
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Partial { detail }, .. } => {
                assert!(detail.contains("not the file"), "{detail}")
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), b"overwritten rubbish");
        assert_eq!(candidate.hash.sha1_hex().unwrap(), real_sha1);
        assert!(candidate.hash.sha256.is_none(), "a contradicted carve claimed the identity");
    }

    #[test]
    fn a_carve_over_reallocated_clusters_is_partial_on_the_bitmap_alone() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        let record =
            builder.file(ROOT_RECORD, "gone.exe", &sample, Presence::DeletedClustersReused);
        let volume = builder.open();

        let mut candidate = deleted_candidate("C:\\gone.exe", record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Partial { detail }, .. } => {
                assert!(detail.contains("reallocated"), "{detail}");
                assert!(detail.contains("4 of its 4 clusters"), "{detail}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!(candidate.hash.is_empty(), "a partial carve claimed an identity");
    }

    #[test]
    fn a_reallocated_mft_record_is_refused_rather_than_carved() {
        let mut builder = Builder::new();
        let record = builder.file(
            ROOT_RECORD,
            "gone.exe",
            b"somebody else's document",
            Presence::RecordReallocatedTo("innocent.docx"),
        );
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = deleted_candidate("C:\\gone.exe", record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Failed { reason } => {
                assert!(reason.contains("reallocated"), "{reason}");
                assert!(reason.contains("innocent.docx"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(!out.path.join("C001.bin").exists(), "bytes were written for a refused carve");
        assert!(candidate.hash.is_empty());
    }

    #[test]
    fn a_file_still_on_the_volume_is_read_rather_than_reconstructed() {
        let sample = sample_bytes();
        let mut builder = Builder::new();
        builder.file(ROOT_RECORD, "present.exe", &sample, Presence::Live);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = candidate_for("C:\\present.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        match &acquisition {
            Acquisition::Bytes { via, recovery, .. } => {
                assert_eq!(*via, ArtifactSource::Mft);
                assert_eq!(*recovery, Recovery::Intact);
            }
            other => panic!("expected intact bytes, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
    }

    fn backup_stream(stream_id: u32, name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&stream_id.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        v.extend_from_slice(&name_bytes);
        v.extend_from_slice(data);
        v
    }

    fn resource_data_blob(sample: &[u8]) -> Vec<u8> {
        let mut plain = backup_stream(0x03, "", b"\x01\x00\x04\x80security-descriptor");
        plain.extend(backup_stream(0x01, "", sample));
        plain.extend(backup_stream(
            0x04,
            ":Zone.Identifier:$DATA",
            b"[ZoneTransfer]\r\nZoneId=3\r\n",
        ));
        quarantine::decrypt(&plain)
    }

    const RESOURCE_ID: &str = "3818F477CB70846BA5AB4B7E356E5C3B4D6345DD";

    fn quarantined_volume(
        sample: &[u8],
        original: &str,
        claimed_size: Option<u64>,
    ) -> (Volume<std::io::Cursor<Vec<u8>>>, QuarantineStore) {
        let mut builder = Builder::new();
        let relative = quarantine::resource_data_relative_path(RESOURCE_ID).unwrap();
        let (fan_out, id) = relative.split_once('\\').unwrap();
        let dir = builder.directories(
            ROOT_RECORD,
            &format!("{}\\{fan_out}", QUARANTINE_RESOURCE_DATA.trim_start_matches('\\')),
        );
        builder.file(dir, id, &resource_data_blob(sample), Presence::Live);

        let mut store = QuarantineStore::new();
        store.add(vec![QuarantinedFile {
            path: path(original),
            resource_id: RESOURCE_ID.to_string(),
            threat: Some("Trojan:Win32/Wacatac.B!ml".into()),
            claimed_size,
        }]);
        (builder.open(), store)
    }

    #[test]
    fn a_quarantined_sample_is_recovered_from_the_defender_store() {
        let sample = sample_bytes();
        let original = "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe";
        let (volume, store) = quarantined_volume(&sample, original, Some(sample.len() as u64));

        let out = case_sample_dir();
        let mut candidate = candidate_for(original);
        let acquisition = acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Bytes { via, size, recovery, .. } => {
                assert_eq!(*via, ArtifactSource::DefenderQuarantine);
                assert_eq!(*size, sample.len() as u64);
                match recovery {
                    Recovery::Unverified { basis } => {
                        assert!(basis.contains("exactly the size"), "{basis}");
                        assert!(basis.contains("no digest"), "{basis}");
                    }
                    other => panic!("expected Unverified, got {other:?}"),
                }
            }
            other => panic!("expected recovered bytes, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample, "the payload is not the sample");
        assert_eq!(candidate.hash.sha256_hex(), FileHash::compute(&sample).sha256_hex());
    }

    #[test]
    fn a_quarantined_sample_an_artifact_hashed_comes_back_confirmed() {
        let sample = sample_bytes();
        let original = "C:\\Users\\bob\\dropper.exe";
        let (volume, store) = quarantined_volume(&sample, original, Some(sample.len() as u64));

        let mut candidate = candidate_for(original);
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path(original),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_sha1_hex(&FileHash::compute(&sample).sha1_hex().unwrap()).unwrap(),
            ),
        );

        let acquisition = acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Confirmed { against }, .. } => {
                assert_eq!(against, "Amcache")
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn a_payload_the_entry_disagrees_with_is_refused() {
        let sample = sample_bytes();
        let original = "C:\\Users\\bob\\dropper.exe";
        let (volume, store) = quarantined_volume(&sample, original, Some(999));

        let out = case_sample_dir();
        let mut candidate = candidate_for(original);
        match acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        ) {
            Acquisition::Failed { reason } => {
                assert!(reason.contains("999-byte file"), "{reason}");
                assert!(reason.contains("not offered as the sample"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(candidate.hash.is_empty());
    }

    #[test]
    fn quarantine_outranks_carving_when_both_are_available() {
        let sample = sample_bytes();
        let original = "C:\\Users\\bob\\dropper.exe";

        let mut builder = Builder::new();
        let relative = quarantine::resource_data_relative_path(RESOURCE_ID).unwrap();
        let (fan_out, id) = relative.split_once('\\').unwrap();
        let dir = builder.directories(
            ROOT_RECORD,
            &format!("{}\\{fan_out}", QUARANTINE_RESOURCE_DATA.trim_start_matches('\\')),
        );
        builder.file(dir, id, &resource_data_blob(&sample), Presence::Live);
        let users = builder.directories(ROOT_RECORD, "Users\\bob");
        let record =
            builder.file(users, "dropper.exe", b"stale carved fragments", Presence::Deleted);
        let volume = builder.open();

        let mut store = QuarantineStore::new();
        store.add(vec![QuarantinedFile {
            path: path(original),
            resource_id: RESOURCE_ID.to_string(),
            threat: None,
            claimed_size: Some(sample.len() as u64),
        }]);

        let out = case_sample_dir();
        let mut candidate = deleted_candidate(original, record);
        let acquisition = acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        match &acquisition {
            Acquisition::Bytes { via, .. } => assert_eq!(*via, ArtifactSource::DefenderQuarantine),
            other => panic!("expected the quarantine to win, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
    }

    #[test]
    fn a_quarantine_payload_that_is_gone_still_leaves_the_carve_to_try() {
        let sample = sample_bytes();
        let original = "C:\\Users\\bob\\dropper.exe";

        let mut builder = Builder::new();
        let users = builder.directories(ROOT_RECORD, "Users\\bob");
        let record = builder.file(users, "dropper.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let mut store = QuarantineStore::new();
        store.add(vec![QuarantinedFile {
            path: path(original),
            resource_id: RESOURCE_ID.to_string(),
            threat: Some("Trojan:Win32/Wacatac.B!ml".into()),
            claimed_size: Some(sample.len() as u64),
        }]);

        let out = case_sample_dir();
        let mut candidate = deleted_candidate(original, record);
        let acquisition = acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        match &acquisition {
            Acquisition::Bytes { via, recovery, .. } => {
                assert_eq!(*via, ArtifactSource::Mft);
                assert!(matches!(recovery, Recovery::Unverified { .. }), "{recovery:?}");
            }
            other => panic!("the carve should have run after the quarantine failed, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), sample);
    }

    #[test]
    fn a_missing_quarantine_payload_says_so() {
        let mut builder = Builder::new();
        builder.directories(ROOT_RECORD, "Windows");
        let volume = builder.open();

        let mut store = QuarantineStore::new();
        store.add(vec![QuarantinedFile {
            path: path("C:\\Users\\bob\\dropper.exe"),
            resource_id: RESOURCE_ID.to_string(),
            threat: Some("Trojan:Win32/Wacatac.B!ml".into()),
            claimed_size: Some(64),
        }]);

        let mut candidate = candidate_for("C:\\Users\\bob\\dropper.exe");
        match acquire(
            &volume,
            &store,
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        ) {
            Acquisition::Failed { reason } => {
                assert!(reason.contains("Trojan:Win32/Wacatac.B!ml"), "{reason}");
                assert!(reason.contains("could not be read"), "{reason}");
            }
            other => panic!("expected a stated failure, got {other:?}"),
        }
    }

    #[test]
    fn a_live_files_identity_is_its_bytes_not_an_artifacts_memory_of_it() {
        let sample = sample_bytes();
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
        builder.file(dir, "dropper.exe", &sample, Presence::Live);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = candidate_for("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe");
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(stale).unwrap()),
        );
        assert_eq!(candidate.hash.sha1_hex().as_deref(), Some(stale), "the setup itself");

        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );

        let computed = FileHash::compute(&sample);
        assert_eq!(candidate.hash.sha1_hex(), computed.sha1_hex(), "Amcache's SHA-1 was kept");
        assert_eq!(candidate.hash.sha256_hex(), computed.sha256_hex());

        assert_eq!(
            FileHash::compute(&saved_bytes(&acquisition, &out.path)).sha256_hex(),
            candidate.hash.sha256_hex()
        );

        let disagreements: Vec<_> = candidate.hash_disagreements().collect();
        assert_eq!(disagreements.len(), 1, "{:?}", candidate.hash_checks);
        assert_eq!(disagreements[0].recorded_by, "Amcache");
        assert_eq!(disagreements[0].algorithm, "sha1");
        assert_eq!(disagreements[0].recorded, stale);
        assert_eq!(disagreements[0].computed, computed.sha1_hex().unwrap());
    }

    #[test]
    fn an_agreeing_artifact_hash_leaves_a_match_and_no_disagreement() {
        let sample = sample_bytes();
        let true_sha1 = FileHash::compute(&sample).sha1_hex().unwrap();

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob");
        builder.file(dir, "dropper.exe", &sample, Presence::Live);
        let volume = builder.open();

        let mut candidate = candidate_for("C:\\Users\\bob\\dropper.exe");
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\dropper.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&true_sha1).unwrap()),
        );

        acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );

        assert_eq!(candidate.hash_disagreements().count(), 0);
        assert_eq!(candidate.hash_checks.len(), 1);
        assert!(candidate.hash_checks[0].agrees);
        assert_eq!(candidate.hash_checks[0].recorded_by, "Amcache");
    }

    #[test]
    fn contradicted_fragments_are_hashed_without_becoming_the_identity() {
        let sample = sample_bytes();
        let recorded = FileHash::compute(b"the file as Amcache saw it");

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob");
        let record = builder.file(dir, "dropper.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = deleted_candidate("C:\\Users\\bob\\dropper.exe", record);
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\dropper.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&recorded.sha1_hex().unwrap()).unwrap()),
        );

        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        assert!(
            matches!(&acquisition, Acquisition::Bytes { recovery: Recovery::Partial { .. }, .. }),
            "{acquisition:?}"
        );

        assert_eq!(candidate.hash.sha1_hex(), recorded.sha1_hex());
        let acquired = candidate.acquired_hash.clone().expect("the fragments were hashed");
        assert_eq!(acquired.sha256_hex(), FileHash::compute(&sample).sha256_hex());
        assert_eq!(candidate.hash_disagreements().count(), 1);
    }

    #[test]
    fn intact_is_claimed_only_for_a_file_read_where_it_lives() {
        let sample = sample_bytes();

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob");
        builder.file(dir, "live.exe", &sample, Presence::Live);
        let deleted = builder.file(dir, "gone.exe", &sample, Presence::Deleted);
        let volume = builder.open();

        let mut live = candidate_for("C:\\Users\\bob\\live.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut live,
            &case_sample_dir(),
        );
        assert!(
            matches!(acquisition, Acquisition::Bytes { recovery: Recovery::Intact, .. }),
            "{acquisition:?}"
        );

        let mut carved = deleted_candidate("C:\\Users\\bob\\gone.exe", deleted);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut carved,
            &case_sample_dir(),
        );
        match acquisition {
            Acquisition::Bytes { recovery, .. } => assert!(
                !matches!(recovery, Recovery::Intact),
                "a carve is never Intact: {recovery:?}"
            ),
            other => panic!("expected recovered bytes, got {other:?}"),
        }
    }

    fn recycled_volume(
        builder: &mut Builder,
        sample: &[u8],
        original: &str,
        claimed_size: u64,
    ) -> RecycleBinStore {
        let dir = builder.directories(ROOT_RECORD, "$Recycle.Bin\\S-1-5-21-1");
        builder.file(dir, "$RK9C8D3.exe", sample, Presence::Live);
        let mut store = RecycleBinStore::new();
        store.add(
            &path(original),
            RecycledPointer {
                data_path: "\\$Recycle.Bin\\S-1-5-21-1\\$RK9C8D3.exe".into(),
                info_path: "\\$Recycle.Bin\\S-1-5-21-1\\$IK9C8D3.exe".into(),
                original_raw: original.into(),
                claimed_size,
                deleted: Some("2026-05-09 18:54:03Z".into()),
                layout: "version 2 (variable-length name)",
            },
        );
        store
    }

    #[test]
    fn the_quarantine_outranks_the_recycle_bin() {
        let quarantined = b"MZ the bytes Defender kept".to_vec();
        let recycled = b"MZ a different file in the bin".to_vec();
        let original = "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svchost.exe";

        let mut builder = Builder::new();
        let relative = quarantine::resource_data_relative_path(RESOURCE_ID).unwrap();
        let (fan_out, id) = relative.split_once('\\').unwrap();
        let qdir = builder.directories(
            ROOT_RECORD,
            &format!("{}\\{fan_out}", QUARANTINE_RESOURCE_DATA.trim_start_matches('\\')),
        );
        builder.file(qdir, id, &resource_data_blob(&quarantined), Presence::Live);
        let bin = recycled_volume(&mut builder, &recycled, original, recycled.len() as u64);
        let volume = builder.open();

        let mut qstore = QuarantineStore::new();
        qstore.add(vec![QuarantinedFile {
            path: path(original),
            resource_id: RESOURCE_ID.to_string(),
            threat: Some("Trojan:Win32/Wacatac.B!ml".into()),
            claimed_size: Some(quarantined.len() as u64),
        }]);

        let out = case_sample_dir();
        let mut candidate = candidate_for(original);
        let acquisition = acquire(
            &volume,
            &qstore,
            &bin,
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        match &acquisition {
            Acquisition::Bytes { via, .. } => {
                assert_eq!(*via, ArtifactSource::DefenderQuarantine)
            }
            other => panic!("expected the quarantine payload, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), quarantined);
    }

    #[test]
    fn the_recycle_bin_outranks_a_carve() {
        let recycled = b"MZ the whole file, sitting in the bin".to_vec();
        let original = "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svchost.exe";

        let mut builder = Builder::new();
        let vendor = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Roaming\\Vendor");
        let record = builder.file(vendor, "svchost.exe", b"carved fragments", Presence::Deleted);
        let bin = recycled_volume(&mut builder, &recycled, original, recycled.len() as u64);
        let volume = builder.open();

        let out = case_sample_dir();
        let mut candidate = deleted_candidate(original, record);
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &bin,
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &out,
        );
        match &acquisition {
            Acquisition::Bytes { via, .. } => assert_eq!(*via, ArtifactSource::RecycleBin),
            other => panic!("expected the bin's copy, got {other:?}"),
        }
        assert_eq!(saved_bytes(&acquisition, &out.path), recycled);
    }

    #[test]
    fn an_unreadable_r_entry_fails_with_a_reason_and_does_not_end_the_chain() {
        let original = "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svchost.exe";
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "$Recycle.Bin\\S-1-5-21-1");
        builder.file(dir, "desktop.ini", b"[.ShellClassInfo]", Presence::Live);
        let mut bin = RecycleBinStore::new();
        bin.add(
            &path(original),
            RecycledPointer {
                data_path: "\\$Recycle.Bin\\S-1-5-21-1\\$RK9C8D3.exe".into(),
                info_path: "\\$Recycle.Bin\\S-1-5-21-1\\$IK9C8D3.exe".into(),
                original_raw: original.into(),
                claimed_size: 4096,
                deleted: None,
                layout: "version 2 (variable-length name)",
            },
        );
        let volume = builder.open();

        let mut candidate = candidate_for(original);
        candidate.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path(original),
                ObservationKind::HashRecovered,
            )
            .with_hash(
                FileHash::from_sha1_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
            ),
        );

        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &bin,
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );
        match &acquisition {
            Acquisition::HashOnly { via } => assert_eq!(*via, ArtifactSource::Amcache),
            other => panic!("the chain must carry on past a failed bin read, got {other:?}"),
        }
    }

    #[test]
    fn a_path_the_bin_does_not_hold_is_not_answered_from_the_bin() {
        let mut builder = Builder::new();
        let bin = recycled_volume(
            &mut builder,
            b"MZ somebody else's deleted file",
            "C:\\Users\\bob\\Desktop\\other.exe",
            31,
        );
        let volume = builder.open();

        let mut candidate = candidate_for("C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svchost.exe");
        let acquisition = acquire(
            &volume,
            &QuarantineStore::new(),
            &bin,
            &ShadowStore::none(),
            &OrphanIndex::default(),
            &RecoveredNames::default(),
            &GhostIndex::default(),
            &mut ClusterMap::new(),
            &mut candidate,
            &case_sample_dir(),
        );
        assert!(
            matches!(acquisition, Acquisition::Failed { .. }),
            "the bin answered for a path it does not hold: {acquisition:?}"
        );
    }
}

#[cfg(test)]
mod shadow_copy_tests {
    use super::*;
    use crate::testimage::{Builder, Presence, ROOT_RECORD};
    use mm_core::{CandidateId, NormalizedPath, Observation, ObservationKind};
    use std::io::Cursor;

    const BLOCK: usize = 0x4000;
    const VOLUME_HEADER_AT: usize = 0x1e00;
    const TOTAL_CLUSTERS: u64 = 1024;
    const MFT_CLUSTERS: u64 = 64;

    const VSS_IDENTIFIER: [u8; 16] = [
        0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7,
        0x52,
    ];
    const SNAPSHOT_FILETIME: u64 = 133_485_408_000_000_000;

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn vss_block(record_type: u32, offset: u64, next: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK];
        b[..16].copy_from_slice(&VSS_IDENTIFIER);
        put32(&mut b, 0x10, 1);
        put32(&mut b, 0x14, record_type);
        put64(&mut b, 0x20, offset);
        put64(&mut b, 0x28, next);
        b
    }

    fn volume_where_only_a_shadow_copy_has(
        path: &str,
        content: &[u8],
        presence: Presence,
    ) -> Vec<u8> {
        let leaf = path.rsplit('\\').next().expect("a leaf name");

        let mut with = Builder::with_geometry(MFT_CLUSTERS, TOTAL_CLUSTERS);
        with.file(ROOT_RECORD, leaf, content, Presence::Live);
        let present = with.bytes();

        let mut without = Builder::with_geometry(MFT_CLUSTERS, TOTAL_CLUSTERS);
        without.file(ROOT_RECORD, leaf, content, presence);
        let mut image = without.bytes();

        assert_eq!(present.len(), image.len(), "both states must be one geometry");
        let length = image.len();

        let store_start = (length - 1024 * 1024) & !(BLOCK - 1);
        let catalog_at = store_start;
        let list_at = store_start + BLOCK;
        let mut stash_at = store_start + 2 * BLOCK;

        let mut descriptors: Vec<(u64, u64)> = Vec::new();
        for start in (0..store_start).step_by(BLOCK) {
            let end = start + BLOCK;
            if present[start..end] == image[start..end] {
                continue;
            }
            assert!(stash_at + BLOCK <= length, "the fixture outgrew its free space");
            image[stash_at..stash_at + BLOCK].copy_from_slice(&present[start..end]);
            descriptors.push((start as u64, stash_at as u64));
            stash_at += BLOCK;
        }
        assert!(
            !descriptors.is_empty(),
            "deleting the file changed nothing, so the fixture proves nothing"
        );

        let mut header = vss_block(1, VOLUME_HEADER_AT as u64, 0);
        put64(&mut header, 0x30, catalog_at as u64);
        image[VOLUME_HEADER_AT..VOLUME_HEADER_AT + 0x80].copy_from_slice(&header[..0x80]);

        let mut catalog = vss_block(2, catalog_at as u64, 0);
        put64(&mut catalog, 0x80, 2);
        put64(&mut catalog, 0x88, length as u64);
        for i in 0..16 {
            catalog[0x90 + i] = 0xA5;
        }
        put64(&mut catalog, 0xA0, 1);
        put64(&mut catalog, 0xB0, SNAPSHOT_FILETIME);
        put64(&mut catalog, 0x100, 3);
        put64(&mut catalog, 0x108, list_at as u64);
        for i in 0..16 {
            catalog[0x110 + i] = 0xA5;
        }
        put64(&mut catalog, 0x120, store_start as u64);
        image[catalog_at..catalog_at + BLOCK].copy_from_slice(&catalog);

        let mut list = vss_block(3, list_at as u64, 0);
        for (i, (original, stored)) in descriptors.iter().enumerate() {
            let at = 0x80 + i * 0x20;
            assert!(at + 0x20 <= BLOCK, "more descriptors than one block holds");
            put64(&mut list, at, *original);
            put64(&mut list, at + 0x10, *stored);
        }
        image[list_at..list_at + BLOCK].copy_from_slice(&list);

        image
    }

    fn open(image: Vec<u8>) -> Volume<Cursor<Vec<u8>>> {
        Volume::open(Cursor::new(image), "synthetic").expect("the spliced volume still opens")
    }

    fn candidate(path_str: &str) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -9.2);
        c.path = NormalizedPath::parse(path_str);
        c
    }

    fn sample_dir() -> SampleDir {
        SampleDir { path: super::tests::case_dir(), relative: "sample", write_out: true }
    }

    fn saved(acquisition: &Acquisition, dir: &std::path::Path) -> Vec<u8> {
        match acquisition {
            Acquisition::Bytes { saved_as, .. } => {
                std::fs::read(dir.join(saved_as.replace("sample/", ""))).expect("the saved sample")
            }
            other => panic!("expected recovered bytes, got {other:?}"),
        }
    }

    #[test]
    fn a_file_deleted_from_the_volume_is_recovered_from_a_shadow_copy() {
        let sample = b"MZ shadow-copied payload, whole".repeat(9);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);

        assert!(!volume.exists(r"c:\payload.exe"), "the file must be gone from the live volume");

        let shadows = ShadowStore::open(&volume);
        assert_eq!(shadows.len(), 1, "refusals: {:?}", shadows.refusals());

        let out = sample_dir();
        let mut c = candidate(r"C:\payload.exe");
        let acquisition = from_shadow_copy(&shadows, &mut c, &out).expect("a recovery");

        assert_eq!(
            saved(&acquisition, &out.path),
            sample,
            "the analyst was handed the wrong bytes"
        );
        match &acquisition {
            Acquisition::Bytes { via: ArtifactSource::VolumeShadowCopy { snapshot }, .. } => {
                assert!(snapshot.starts_with("2024-"), "the snapshot must be dated: {snapshot}");
            }
            other => panic!("expected a shadow copy recovery, got {other:?}"),
        }
    }

    #[test]
    fn a_store_one_cluster_larger_than_the_filesystem_is_still_this_volume() {
        let sample = b"MZ shadow-copied payload, whole".repeat(9);

        for (excess, opened) in [(0u64, 1usize), (4096, 1), (1024 * 1024, 1), (2 << 30, 0)] {
            let mut image =
                volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
            let filesystem = open(image.clone()).length();
            let catalog_at = (image.len() - 1024 * 1024) & !(BLOCK - 1);
            put64(&mut image, catalog_at + 0x88, filesystem + excess);

            let volume = open(image);
            let shadows = ShadowStore::open(&volume);
            assert_eq!(
                shadows.len(),
                opened,
                "a store {excess} bytes larger than the {filesystem}-byte filesystem: {:?}",
                shadows.refusals()
            );
            if opened == 0 {
                assert!(
                    shadows.refusals().iter().any(|r| r.contains("describes a")),
                    "the refusal must say what it refused: {:?}",
                    shadows.refusals()
                );
            }
        }
    }

    #[test]
    fn an_unconfirmed_shadow_copy_recovery_is_unverified_and_dated() {
        let sample = b"payload".repeat(64);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);

        let mut c = candidate(r"C:\payload.exe");
        let acquisition = from_shadow_copy(&shadows, &mut c, &sample_dir()).expect("a recovery");
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Unverified { basis }, .. } => {
                assert!(basis.contains("2024-"), "{basis}");
                assert!(basis.contains("shadow copy"), "{basis}");
                assert!(
                    basis.contains("nothing independent confirms"),
                    "the caveat must say what was NOT established: {basis}"
                );
            }
            other => panic!("expected an unverified recovery, got {other:?}"),
        }
        assert!(
            !matches!(acquisition, Acquisition::Bytes { recovery: Recovery::Intact, .. }),
            "a shadow copy is a different point in time and can never be Intact"
        );
    }

    #[test]
    fn an_unconfirmed_shadow_copy_recovery_does_not_claim_the_candidates_hash() {
        let sample = b"payload".repeat(64);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);

        let mut c = candidate(r"C:\payload.exe");
        let _ = from_shadow_copy(&shadows, &mut c, &sample_dir()).expect("a recovery");
        assert!(
            c.hash.is_empty() || c.hash.sha256_hex() != FileHash::compute(&sample).sha256_hex(),
            "an unconfirmed snapshot read must not become the candidate's identity"
        );
    }

    #[test]
    fn a_shadow_copy_recovery_an_artifact_confirms_is_confirmed() {
        let sample = b"MZ confirmed payload".repeat(20);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);

        let mut c = candidate(r"C:\payload.exe");
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                NormalizedPath::parse(r"C:\payload.exe").unwrap(),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(&sample)),
        );

        let acquisition = from_shadow_copy(&shadows, &mut c, &sample_dir()).expect("a recovery");
        match &acquisition {
            Acquisition::Bytes { recovery: Recovery::Confirmed { against }, .. } => {
                assert_eq!(against, "Amcache");
            }
            other => panic!("expected a confirmed recovery, got {other:?}"),
        }
    }

    #[test]
    fn a_shadow_copy_is_preferred_over_clusters_that_were_reused() {
        let sample = b"the real payload, whole".repeat(30);
        let image = volume_where_only_a_shadow_copy_has(
            r"C:\payload.exe",
            &sample,
            Presence::DeletedClustersReused,
        );
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);
        assert_eq!(shadows.len(), 1, "refusals: {:?}", shadows.refusals());

        let out = sample_dir();
        let mut c = candidate(r"C:\payload.exe");
        let acquisition = from_shadow_copy(&shadows, &mut c, &out).expect("a recovery");
        assert_eq!(
            saved(&acquisition, &out.path),
            sample,
            "the snapshot holds the real bytes even though the clusters were reused"
        );
    }

    #[test]
    fn a_volume_without_shadow_copies_reports_their_absence() {
        let mut builder = Builder::with_geometry(MFT_CLUSTERS, TOTAL_CLUSTERS);
        builder.file(ROOT_RECORD, "ordinary.exe", b"content", Presence::Live);
        let volume = open(builder.bytes());

        let shadows = ShadowStore::open(&volume);
        assert!(shadows.is_empty());
        assert_eq!(shadows.catalogued(), 0);
        assert!(shadows.refusals().is_empty(), "absence is not a refusal");
        let line = shadows.coverage_line();
        assert!(line.contains("none on this volume"), "{line}");
        assert!(
            line.contains("deleted"),
            "the line must offer the reading an analyst needs: {line}"
        );
    }

    #[test]
    fn the_coverage_line_states_how_many_and_when() {
        let sample = b"payload".repeat(64);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let line = ShadowStore::open(&volume).coverage_line();
        assert!(line.contains("volume shadow copies"), "{line}");
        assert!(line.contains("2024-"), "{line}");
    }

    #[test]
    fn a_candidate_without_a_path_is_not_looked_up() {
        let sample = b"payload".repeat(64);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);

        let mut c = Candidate::new(CandidateId(2), -9.2);
        assert!(from_shadow_copy(&shadows, &mut c, &sample_dir()).is_none());
    }

    #[test]
    fn a_path_the_snapshot_does_not_hold_falls_through() {
        let sample = b"payload".repeat(64);
        let image =
            volume_where_only_a_shadow_copy_has(r"C:\payload.exe", &sample, Presence::Deleted);
        let volume = open(image);
        let shadows = ShadowStore::open(&volume);

        let mut c = candidate(r"C:\nowhere\absent.exe");
        assert!(from_shadow_copy(&shadows, &mut c, &sample_dir()).is_none());
    }
}

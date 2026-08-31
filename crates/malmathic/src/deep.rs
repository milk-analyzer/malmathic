use std::io::{Read, Seek};
use std::time::{Duration, Instant};

use mm_core::{Acquisition, ArtifactSource, Candidate, FileHash, ObservationKind, Recovery};
use mm_raw::Volume;

use crate::acquire::{bit, save, ClusterMap, SampleDir, MAX_SAMPLE_BYTES};

const CHUNK: usize = 1024 * 1024;

const HEADER_WINDOW: usize = 8 * 1024;

const MAX_READ_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

const MAX_HEADERS: u64 = 4_000_000;

const MAX_HASH_ATTEMPTS: u64 = 200_000;

pub const MAX_TARGETS: usize = 32;

const MIN_SELF_NAME_STEM: usize = 3;

const TIME_BUDGET: Duration = Duration::from_secs(20 * 60);

#[derive(Clone, Debug)]
pub struct Target {
    pub index: usize,
    pub label: String,
    pub recorded: Option<(ArtifactSource, FileHash)>,
    pub stem: String,
}

impl Target {
    fn describe(&self) -> String {
        match &self.recorded {
            Some((source, hash)) => format!(
                "the {} {} recorded",
                hash.best().unwrap_or_else(|| "digest".into()),
                source.label()
            ),
            None => format!("the name `{}` an image may carry inside itself", self.stem),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matched {
    Digest { against: String },
    SelfName { carried: String },
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub index: usize,
    pub lcn: u64,
    pub bytes: Vec<u8>,
    pub computed: FileHash,
    pub matched: Matched,
}

#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub free_clusters: u64,
    pub scanned_clusters: u64,
    pub bytes_read: u64,
    pub headers: u64,
    pub hashed: u64,
    pub hits: Vec<Hit>,
    pub stopped: Option<String>,
    pub elapsed: Duration,
}

impl Scan {
    pub fn exhaustive(&self) -> bool {
        self.stopped.is_none()
    }
}

pub fn scan<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    targets: &[Target],
) -> Option<Scan> {
    if targets.is_empty() {
        return None;
    }
    let cluster_size = volume.cluster_size();
    if cluster_size == 0 || cluster_size > CHUNK as u64 {
        return None;
    }
    let total = volume.total_clusters();
    if total == 0 {
        return None;
    }
    let bits = clusters.bits(volume)?;

    let started = Instant::now();
    let mut scan = Scan::default();
    let mut buffer = vec![0u8; CHUNK + HEADER_WINDOW];

    for run in FreeRuns::new(bits, total) {
        scan.free_clusters = scan.free_clusters.saturating_add(run.length);
    }

    'runs: for run in FreeRuns::new(bits, total) {
        let run_bytes = run.length.saturating_mul(cluster_size);
        let mut at: u64 = 0;
        while at < run_bytes {
            if let Some(reason) = exhausted(&scan, started) {
                match &mut scan.stopped {
                    Some(existing) => existing.push_str(&format!("; and {reason}")),
                    None => scan.stopped = Some(reason),
                }
                break 'runs;
            }
            let remaining = run_bytes - at;
            let want = usize::try_from(remaining.min((CHUNK + HEADER_WINDOW) as u64))
                .unwrap_or(CHUNK + HEADER_WINDOW);
            let lcn = run.lcn + at / cluster_size;
            if volume.read_clusters(lcn, &mut buffer[..want]).is_err() {
                scan.stopped.get_or_insert_with(|| {
                    format!(
                        "at least one span of free space could not be read (cluster {lcn}), so \
                         the clusters it covers were not searched"
                    )
                });
                at = at.saturating_add(CHUNK as u64);
                continue;
            }
            scan.bytes_read = scan.bytes_read.saturating_add(want as u64);
            let searchable = want.min(CHUNK);
            scan.scanned_clusters =
                scan.scanned_clusters.saturating_add((searchable as u64) / cluster_size);

            let mut offset = 0usize;
            while offset + 2 <= searchable {
                if buffer[offset] == b'M' && buffer[offset + 1] == b'Z' {
                    let start = at + offset as u64;
                    examine(
                        volume,
                        &buffer[offset..want],
                        run.lcn + start / cluster_size,
                        run_bytes - start,
                        targets,
                        &mut scan,
                    );
                    if scan.hits.len() >= targets.len() {
                        break 'runs;
                    }
                }
                offset += cluster_size as usize;
            }
            at = at.saturating_add(CHUNK as u64);
        }
    }

    scan.elapsed = started.elapsed();
    Some(scan)
}

fn exhausted(scan: &Scan, started: Instant) -> Option<String> {
    if scan.bytes_read >= MAX_READ_BYTES {
        return Some(format!(
            "it reached its {} GiB read limit",
            MAX_READ_BYTES / (1024 * 1024 * 1024)
        ));
    }

    if scan.headers >= MAX_HEADERS {
        return Some(format!("it reached its limit of {MAX_HEADERS} PE headers followed"));
    }
    if scan.hashed >= MAX_HASH_ATTEMPTS {
        return Some(format!("it reached its limit of {MAX_HASH_ATTEMPTS} spans hashed"));
    }
    if started.elapsed() >= TIME_BUDGET {
        return Some(format!("it reached its {}-minute time limit", TIME_BUDGET.as_secs() / 60));
    }
    None
}

fn examine<R: Read + Seek>(
    volume: &Volume<R>,
    window: &[u8],
    lcn: u64,
    contiguous: u64,
    targets: &[Target],
    scan: &mut Scan,
) {
    let Some(length) = pe_image_length(window) else { return };
    scan.headers = scan.headers.saturating_add(1);

    if length > contiguous {
        return;
    }
    if scan.hashed >= MAX_HASH_ATTEMPTS || scan.bytes_read >= MAX_READ_BYTES {
        return;
    }
    let Ok(size) = usize::try_from(length) else { return };

    let bytes = match window.get(..size) {
        Some(inside) => inside.to_vec(),
        None => {
            let mut bytes = vec![0u8; size];
            if volume.read_clusters(lcn, &mut bytes).is_err() {
                return;
            }
            scan.bytes_read = scan.bytes_read.saturating_add(length);
            bytes
        }
    };
    scan.hashed = scan.hashed.saturating_add(1);
    let computed = FileHash::compute(&bytes);
    let mut carried: Option<Vec<String>> = None;

    for target in targets.iter().take(MAX_TARGETS) {
        if scan.hits.iter().any(|hit| hit.index == target.index) {
            continue;
        }
        let matched = match &target.recorded {
            Some((source, recorded)) if recorded.agrees_with(&computed) => {
                Matched::Digest { against: source.label() }
            }
            Some(_) => continue,
            None => {
                let names = carried.get_or_insert_with(|| mm_harvest::pe::self_names(&bytes));
                match names.iter().find(|name| mm_harvest::pe::stem_of(name) == target.stem) {
                    Some(name) => Matched::SelfName { carried: name.clone() },
                    None => continue,
                }
            }
        };
        scan.hits.push(Hit {
            index: target.index,
            lcn,
            bytes: bytes.clone(),
            computed: computed.clone(),
            matched,
        });
    }
}

fn pe_image_length(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return None;
    }
    let lfanew = u32_at(bytes, 0x3c)? as usize;
    if lfanew < 0x40 {
        return None;
    }
    if u32_at(bytes, lfanew)? != 0x0000_4550 {
        return None;
    }
    let coff = lfanew.checked_add(4)?;
    let sections = u16_at(bytes, coff.checked_add(2)?)? as usize;
    let optional_size = u16_at(bytes, coff.checked_add(16)?)? as usize;
    if sections == 0 || sections > 96 {
        return None;
    }
    let optional = coff.checked_add(20)?;
    let magic = u16_at(bytes, optional)?;
    if magic != 0x010b && magic != 0x020b {
        return None;
    }

    let mut end = u64::from(u32_at(bytes, optional.checked_add(60)?)?);

    let count_at = optional.checked_add(if magic == 0x010b { 92 } else { 108 })?;
    let dir_base = optional.checked_add(if magic == 0x010b { 96 } else { 112 })?;
    if u32_at(bytes, count_at)? > 4 {
        let entry = dir_base.checked_add(4 * 8)?;
        let address = u64::from(u32_at(bytes, entry)?);
        let size = u64::from(u32_at(bytes, entry.checked_add(4)?)?);
        if address > 0 && size > 0 {
            end = end.max(address.checked_add(size)?);
        }
    }

    let table = optional.checked_add(optional_size)?;
    for index in 0..sections {
        let section = table.checked_add(index.checked_mul(40)?)?;
        let raw_size = u64::from(u32_at(bytes, section.checked_add(16)?)?);
        let raw_offset = u64::from(u32_at(bytes, section.checked_add(20)?)?);
        if raw_size == 0 {
            continue;
        }
        end = end.max(raw_offset.checked_add(raw_size)?);
    }

    if end == 0 || end > MAX_SAMPLE_BYTES as u64 {
        return None;
    }
    Some(end)
}

#[cfg(test)]
pub(crate) fn pe_image_length_for_test(bytes: &[u8]) -> Option<u64> {
    pe_image_length(bytes)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FreeRun {
    pub lcn: u64,
    pub length: u64,
}

pub(crate) struct FreeRuns<'a> {
    bits: &'a [u8],
    at: u64,
    end: u64,
}

impl<'a> FreeRuns<'a> {
    pub(crate) fn new(bits: &'a [u8], total_clusters: u64) -> Self {
        let covered = (bits.len() as u64).saturating_mul(8);
        FreeRuns { bits, at: 0, end: total_clusters.min(covered) }
    }
}

impl Iterator for FreeRuns<'_> {
    type Item = FreeRun;

    fn next(&mut self) -> Option<FreeRun> {
        while self.at < self.end && bit(self.bits, self.at) != Some(false) {
            self.at += 1;
        }
        if self.at >= self.end {
            return None;
        }
        let lcn = self.at;
        while self.at < self.end && bit(self.bits, self.at) == Some(false) {
            self.at += 1;
        }
        Some(FreeRun { lcn, length: self.at - lcn })
    }
}

fn worth_searching_for(candidate: &Candidate) -> bool {
    match &candidate.acquisition {
        Acquisition::Failed { .. } | Acquisition::HashOnly { .. } | Acquisition::NotAttempted => {}
        Acquisition::Bytes { .. } | Acquisition::Withheld { .. } => return false,
    }
    !candidate.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. }))
}

fn target_for(candidate: &Candidate, index: usize) -> Option<Target> {
    if !worth_searching_for(candidate) {
        return None;
    }
    let recorded = candidate
        .recorded_hash()
        .filter(|(_, hash)| !hash.is_empty())
        .map(|(source, hash)| (source.clone(), hash.clone()));
    let stem = candidate
        .path
        .as_ref()
        .filter(|path| path.is_executable_extension())
        .and_then(|path| path.file_name())
        .map(mm_harvest::pe::stem_of)
        .filter(|stem| stem.len() >= MIN_SELF_NAME_STEM)
        .unwrap_or_default();
    if recorded.is_none() && stem.is_empty() {
        return None;
    }
    Some(Target { index, label: candidate.label(), recorded, stem })
}

pub fn targets(candidates: &[Candidate], order: &[usize]) -> Vec<Target> {
    let mut targets = Vec::new();
    for &index in order {
        if targets.len() >= MAX_TARGETS {
            break;
        }
        let Some(candidate) = candidates.get(index) else { continue };
        if let Some(target) = target_for(candidate, index) {
            targets.push(target);
        }
    }
    targets
}

pub fn over_the_cap(candidates: &[Candidate], order: &[usize]) -> usize {
    let qualified = order
        .iter()
        .filter_map(|&index| Some((index, candidates.get(index)?)))
        .filter(|(index, candidate)| target_for(candidate, *index).is_some())
        .count();
    qualified.saturating_sub(MAX_TARGETS)
}

pub fn unsearchable(candidates: &[Candidate], order: &[usize]) -> Vec<String> {
    let mut names = Vec::new();
    for &index in order {
        let Some(candidate) = candidates.get(index) else { continue };
        if !worth_searching_for(candidate) {
            continue;
        }
        if target_for(candidate, index).is_some() {
            continue;
        }
        names.push(candidate.label());
    }
    names
}

pub fn adopt(candidate: &mut Candidate, hit: &Hit, sample_dir: &SampleDir) -> Acquisition {
    let recovery = match &hit.matched {
        Matched::Digest { against } => Recovery::Confirmed {
            against: format!(
                "the {} {against} recorded — these bytes were found by that digest, at cluster {} \
                 of unallocated space, with no filesystem record naming them",
                hit.computed.best().unwrap_or_else(|| "digest".into()),
                hit.lcn
            ),
        },
        Matched::SelfName { carried } => Recovery::Unverified {
            basis: format!(
                "carved from cluster {} of unallocated space, where no filesystem record names \
                 it. Nothing recorded a digest of this file, so what ties these bytes to this \
                 path is that the image names ITSELF `{carried}` — a name a compiler or linker \
                 wrote into it, in its debug directory or export table, and which matches the \
                 file name the artifacts give. That is the author's word for what the file was \
                 called, not the filesystem's, and a second copy of the same program anywhere on \
                 this disk would carry it too. The bytes are {} long and hash to {}",
                hit.lcn,
                hit.bytes.len(),
                hit.computed.best().unwrap_or_else(|| "nothing".into())
            ),
        },
    };
    let adopt = matches!(hit.matched, Matched::Digest { .. });
    candidate.record_acquired_hash(&hit.computed, adopt);
    save(candidate, &hit.bytes, sample_dir, ArtifactSource::UnallocatedClusters, recovery)
        .unwrap_or_else(|| Acquisition::Failed {
            reason:
                "a matching image was carved from unallocated space but could not be written out"
                    .to_string(),
        })
}

pub fn no_hit_reason(target: &Target, scan: &Scan, previous: &str) -> String {
    let mut reason = previous.trim_end().trim_end_matches('.').to_string();
    reason.push_str(&format!(
        ". A deep scan then read {} of the {} cluster(s) $Bitmap marks free ({} MB) and found {} \
         PE image(s) in unallocated space; none of them answers to {}, so nothing was saved",
        scan.scanned_clusters,
        scan.free_clusters,
        scan.bytes_read / (1024 * 1024),
        scan.headers,
        target.describe(),
    ));
    match &scan.stopped {
        Some(why) => reason.push_str(&format!(
            ". That search was NOT exhaustive — {why} — so the free space it did not reach is \
             UNKNOWN, not empty"
        )),
        None => reason.push_str(
            ". The search covered every free run on the volume. It can only find a file \
             whose clusters are still contiguous and still free, and it measures each \
             image by its own PE headers — so a file NTFS wrote in fragments, and a \
             file with data appended past its last section, both leave it nothing to \
             find. Not finding it is not evidence the bytes are gone",
        ),
    }
    reason
}

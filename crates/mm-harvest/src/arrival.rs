use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use mm_core::arrival::{Admission, Arrival, ArrivalTimeline, Event, FileLife, Role};
use mm_core::CandidateId;
use mm_raw::usn::{self, RecordFate};
use mm_raw::Volume;
use ntfs_core::usn::{UsnReason, UsnRecord};

pub const RADIUS: Duration = Duration::from_secs(60);

pub const MAX_ANCHORS: usize = 32;

pub const MAX_NEIGHBOURS: usize = 16;

pub const MAX_ROWS_PER_FILE: usize = 512;

pub const BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Anchor {
    pub candidate: CandidateId,
    pub display_path: String,
    pub key: String,
    pub record: u64,
    pub probability: f64,
    pub is_finding: bool,
}

pub struct Context<'a> {
    pub candidates: &'a HashMap<String, (CandidateId, f64)>,
    pub threshold: f64,
    pub window: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

pub fn read<R: Read + Seek>(
    volume: &Volume<R>,
    anchors: &[Anchor],
    context: &Context<'_>,
) -> Option<ArrivalTimeline> {
    let started = Instant::now();

    if anchors.is_empty() {
        return None;
    }

    let journal = usn::read_journal(volume);
    if journal.records.is_empty() {
        return None;
    }

    let wanted: HashSet<u64> = anchors.iter().map(|a| a.record).collect();
    let mut by_record: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, row) in journal.records.iter().enumerate() {
        if wanted.contains(&row.mft_entry) {
            by_record.entry(row.mft_entry).or_default().push(index);
        }
    }

    let mut fates: HashMap<(u64, u16), bool> = HashMap::new();
    let mut directories: HashMap<u64, Option<String>> = HashMap::new();
    let mut blocks: Vec<Arrival> = Vec::new();
    let mut named: HashMap<(u64, u16), usize> = HashMap::new();

    for anchor in anchors {
        if blocks.len() >= MAX_ANCHORS || started.elapsed() >= BUDGET {
            break;
        }

        let indices = by_record.get(&anchor.record).map(Vec::as_slice).unwrap_or(&[]);
        let own: Vec<&UsnRecord> = indices
            .iter()
            .map(|&i| &journal.records[i])
            .filter(|row| still_this_file(volume, row.mft_entry, row.mft_sequence, &mut fates))
            .take(MAX_ROWS_PER_FILE)
            .collect();

        let Some(life) = collapse(&own) else {
            if anchor.is_finding {
                blocks.push(Arrival {
                    candidate: anchor.candidate,
                    display_path: anchor.display_path.clone(),
                    probability: anchor.probability,
                    admission: Admission::Finding,
                    directory: None,
                    record: anchor.record,
                    sequence: None,
                    files: Vec::new(),
                });
            }
            continue;
        };

        let admission = if anchor.is_finding {
            Admission::Finding
        } else {
            match (context.window, arrived(&life)) {
                (Some((start, end)), Some(at)) if at >= start && at <= end => {
                    Admission::InIncidentWindow
                }
                _ => continue,
            }
        };

        let parent = own
            .iter()
            .find(|row| row.reason.contains(UsnReason::FILE_CREATE))
            .or_else(|| own.first())
            .map(|row| (row.parent_mft_entry, row.parent_mft_sequence));

        let directory =
            parent.and_then(|(entry, sequence)| resolve(volume, entry, sequence, &mut directories));
        let directory = directory.filter(|d| {
            anchor.key.rsplit_once('\\').map(|(parent, _)| parent).is_some_and(|p| {
                let d = d.to_ascii_lowercase();
                p == d.trim_end_matches('\\') || (p.is_empty() && d == "\\")
            })
        });

        let mut files =
            vec![into_file(&life, Role::Anchor, directory.as_deref(), anchor.display_path.clone())];
        named.insert((life.record, life.sequence), life.rows);

        let centre = arrived(&life).unwrap_or(life.first);
        if let (Some((parent_entry, parent_sequence)), Some(directory)) = (parent, &directory) {
            let mut neighbours = collect_neighbours(
                &journal.records,
                parent_entry,
                parent_sequence,
                (life.record, life.sequence),
                centre,
            );
            neighbours.sort_by(|a, b| {
                offset(a.first, centre)
                    .abs()
                    .partial_cmp(&offset(b.first, centre).abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            neighbours.truncate(MAX_NEIGHBOURS);
            for neighbour in neighbours {
                let path = join(directory, &neighbour.name);
                let role = match context.candidates.get(&path.to_ascii_lowercase()) {
                    Some((id, probability)) => Role::Candidate {
                        id: *id,
                        probability: *probability,
                        below_threshold: *probability < context.threshold,
                    },
                    None => Role::NotACandidate,
                };
                named.insert((neighbour.record, neighbour.sequence), neighbour.rows);
                files.push(into_file(&neighbour, role, Some(directory), path));
            }
        }

        files.sort_by_key(|f| f.first);
        let mut previous: Option<DateTime<Utc>> = None;
        for file in &mut files {
            file.offset_seconds = offset(file.first, centre);
            file.gap_seconds = previous.map(|p| offset(file.first, p));
            previous = Some(file.first);
        }

        blocks.push(Arrival {
            candidate: anchor.candidate,
            display_path: anchor.display_path.clone(),
            probability: anchor.probability,
            admission,
            directory,
            record: life.record,
            sequence: Some(life.sequence),
            files,
        });
    }

    if blocks.is_empty() {
        return None;
    }
    Some(ArrivalTimeline {
        rows_in_journal: journal.records.len(),
        rows_admitted: named.values().sum(),
        files_named: named.len(),
        radius_seconds: RADIUS.as_secs() as i64,
        oldest_record: journal.window().first_time,
        anchors: blocks,
    })
}

struct Life {
    name: String,
    record: u64,
    sequence: u16,
    rows: usize,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    created: Option<DateTime<Utc>>,
    events: Vec<Event>,
}

fn arrived(life: &Life) -> Option<DateTime<Utc>> {
    life.created
}

fn collapse(rows: &[&UsnRecord]) -> Option<Life> {
    let first_row = *rows.first()?;
    let mut first = first_row.timestamp;
    let mut last = first_row.timestamp;
    let mut name = first_row.filename.clone();

    let mut created: Option<DateTime<Utc>> = None;
    let mut deleted: Option<DateTime<Utc>> = None;
    let mut closed: Option<DateTime<Utc>> = None;
    let mut written: Option<DateTime<Utc>> = None;
    let (mut extended, mut overwritten, mut truncated) = (false, false, false);
    let mut renamed: Option<DateTime<Utc>> = None;
    let mut renamed_from: Option<String> = None;
    let mut renamed_to: Option<String> = None;

    for row in rows {
        first = first.min(row.timestamp);
        if row.timestamp >= last {
            last = row.timestamp;
            if !row.filename.is_empty() {
                name = row.filename.clone();
            }
        }
        let reason = row.reason;
        if reason.contains(UsnReason::FILE_CREATE) {
            created = Some(created.map_or(row.timestamp, |t: DateTime<Utc>| t.min(row.timestamp)));
        }
        if reason.contains(UsnReason::FILE_DELETE) {
            deleted = Some(deleted.map_or(row.timestamp, |t: DateTime<Utc>| t.min(row.timestamp)));
        }
        if reason.contains(UsnReason::CLOSE) {
            closed = Some(closed.map_or(row.timestamp, |t: DateTime<Utc>| t.max(row.timestamp)));
        }
        if reason.intersects(
            UsnReason::DATA_EXTEND | UsnReason::DATA_OVERWRITE | UsnReason::DATA_TRUNCATION,
        ) {
            extended |= reason.contains(UsnReason::DATA_EXTEND);
            overwritten |= reason.contains(UsnReason::DATA_OVERWRITE);
            truncated |= reason.contains(UsnReason::DATA_TRUNCATION);
            written = Some(written.map_or(row.timestamp, |t: DateTime<Utc>| t.max(row.timestamp)));
        }
        if reason.contains(UsnReason::RENAME_OLD_NAME) {
            renamed_from = Some(row.filename.clone());
            renamed = Some(renamed.map_or(row.timestamp, |t: DateTime<Utc>| t.min(row.timestamp)));
        }
        if reason.contains(UsnReason::RENAME_NEW_NAME) {
            renamed_to = Some(row.filename.clone());
            renamed = Some(renamed.map_or(row.timestamp, |t: DateTime<Utc>| t.min(row.timestamp)));
        }
    }

    let mut events = Vec::new();
    if let Some(at) = created {
        events.push(Event::Appeared { at });
    }
    if let Some(at) = renamed {
        events.push(Event::Renamed { at, from: renamed_from, to: renamed_to });
    }
    if let Some(at) = written {
        events.push(Event::Written { at, extended, overwritten, truncated });
    }
    if let Some(at) = closed {
        let from = created.unwrap_or(first);
        events.push(Event::Closed { at, after_seconds: offset(at, from) });
    }
    if let Some(at) = deleted {
        events.push(Event::Deleted { at });
    }
    events.sort_by_key(Event::at);

    Some(Life {
        name,
        record: first_row.mft_entry,
        sequence: first_row.mft_sequence,
        rows: rows.len(),
        first,
        last,
        created,
        events,
    })
}

fn collect_neighbours(
    rows: &[UsnRecord],
    parent_entry: u64,
    parent_sequence: u16,
    anchor: (u64, u16),
    at: DateTime<Utc>,
) -> Vec<Life> {
    let radius = RADIUS.as_secs() as f64;
    let mut groups: HashMap<(u64, u16), Vec<&UsnRecord>> = HashMap::new();
    for row in rows {
        if row.parent_mft_entry != parent_entry || row.parent_mft_sequence != parent_sequence {
            continue;
        }
        let key = (row.mft_entry, row.mft_sequence);
        if key == anchor {
            continue;
        }
        let bucket = groups.entry(key).or_default();
        if bucket.len() < MAX_ROWS_PER_FILE {
            bucket.push(row);
        }
    }
    let mut out: Vec<Life> = groups
        .into_values()
        .filter_map(|group| collapse(&group))
        .filter(|life| arrived(life).is_some_and(|when| offset(when, at).abs() <= radius))
        .collect();
    out.sort_by_key(|life| life.first);
    out
}

fn into_file(life: &Life, role: Role, directory: Option<&str>, path: String) -> FileLife {
    FileLife {
        name: life.name.clone(),
        display_path: directory.map(|_| path),
        record: life.record,
        sequence: life.sequence,
        rows: life.rows,
        first: life.first,
        last: life.last,
        role,
        offset_seconds: 0.0,
        gap_seconds: None,
        events: life.events.clone(),
    }
}

fn join(directory: &str, name: &str) -> String {
    if directory == "\\" {
        format!("\\{name}")
    } else {
        format!("{directory}\\{name}")
    }
}

fn offset(a: DateTime<Utc>, b: DateTime<Utc>) -> f64 {
    (a - b).num_milliseconds() as f64 / 1000.0
}

fn still_this_file<R: Read + Seek>(
    volume: &Volume<R>,
    entry: u64,
    sequence: u16,
    cache: &mut HashMap<(u64, u16), bool>,
) -> bool {
    if let Some(hit) = cache.get(&(entry, sequence)) {
        return *hit;
    }
    let verdict = matches!(
        usn::record_fate(volume, entry, sequence),
        RecordFate::SameFile | RecordFate::Freed
    );
    cache.insert((entry, sequence), verdict);
    verdict
}

fn resolve<R: Read + Seek>(
    volume: &Volume<R>,
    entry: u64,
    sequence: u16,
    cache: &mut HashMap<u64, Option<String>>,
) -> Option<String> {
    crate::usn_journal::resolve_directory(volume, entry, sequence, cache, 0)
}

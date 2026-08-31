use ntfs_core::{decode_runlist, FileName, MftRecordHeader, Run};

pub const RECORD_BYTES: usize = 1024;

const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;

const MIN_ATTRIBUTE_BYTES: usize = 0x18;
const MIN_NON_RESIDENT_HEADER: usize = 0x40;
const MAX_ATTRIBUTE_BYTES: usize = RECORD_BYTES;
const MIN_RECORD_USED: usize = 0x38;
const LOG_PAGE_HEADER: usize = 0x40;

const MAX_NAME_CHARS: usize = 255;
const MAX_RUNS: usize = 4096;

const FIRST_PLAUSIBLE_FILETIME: u64 = 116_444_736_000_000_000;
const LAST_PLAUSIBLE_FILETIME: u64 = 159_725_808_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    RecordSlack { record: u64 },
    LogFile { offset: u64 },
}

impl std::fmt::Display for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Found::RecordSlack { record } => {
                write!(f, "the unused tail of $MFT record {record}")
            }
            Found::LogFile { offset } => write!(f, "$LogFile at offset {offset}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ghost {
    pub name: String,
    pub parent: u64,
    pub real_size: u64,
    pub created: u64,
    pub modified: u64,
    pub runs: Vec<Run>,
    pub resident: Option<Vec<u8>>,
    pub found: Found,
}

impl Ghost {
    #[must_use]
    pub fn has_bytes(&self) -> bool {
        self.resident.is_some() || !self.runs.is_empty()
    }

    #[must_use]
    pub fn clusters(&self) -> u64 {
        self.runs.iter().map(|run| run.length).sum()
    }
}

enum Body {
    Resident(Vec<u8>),
    NonResident { runs: Vec<Run>, real_size: u64 },
}

pub fn in_record_slack(record: &[u8], record_number: u64) -> Option<Ghost> {
    let header = MftRecordHeader::parse(record).ok()?;
    if &header.signature != b"FILE" {
        return None;
    }
    let used = header.used_size as usize;
    if used < MIN_RECORD_USED || used >= record.len() {
        return None;
    }
    collect(record, used.next_multiple_of(8), Found::RecordSlack { record: record_number })
}

pub fn in_log_file(bytes: &[u8], budget: usize) -> Vec<Ghost> {
    let mut ghosts = Vec::new();
    for page in ntfs_core::read_record_pages(bytes) {
        let data = &page.data;
        let mut at = LOG_PAGE_HEADER;
        while at + MIN_RECORD_USED <= data.len() {
            if &data[at..at + 4] != b"FILE" {
                at += 8;
                continue;
            }
            let end = (at + RECORD_BYTES).min(data.len());
            if let Some(ghost) = in_log_image(&data[at..end], (page.offset + at) as u64) {
                ghosts.push(ghost);
                if ghosts.len() >= budget {
                    return ghosts;
                }
            }
            at += 8;
        }
    }
    ghosts
}

fn in_log_image(image: &[u8], offset: u64) -> Option<Ghost> {
    let header = MftRecordHeader::parse(image).ok()?;
    if &header.signature != b"FILE" || header.sequence_number == 0 {
        return None;
    }
    let first = header.first_attribute_offset as usize;
    if first < MIN_RECORD_USED || first >= image.len() {
        return None;
    }
    collect(image, first, Found::LogFile { offset }).or_else(|| {
        let mut fixed = image.to_vec();
        ntfs_core::apply_fixup(&mut fixed, 512).ok()?;
        collect(&fixed, first, Found::LogFile { offset })
    })
}

fn collect(buffer: &[u8], from: usize, found: Found) -> Option<Ghost> {
    let mut name: Option<FileName> = None;
    let mut data: Option<Body> = None;

    let mut at = from.next_multiple_of(8);
    while at + MIN_ATTRIBUTE_BYTES <= buffer.len() {
        match attribute_at(buffer, at) {
            Some((ATTR_FILE_NAME, Body::Resident(content))) if name.is_none() => {
                name = FileName::parse(&content).ok().filter(plausible_name);
            }
            Some((ATTR_DATA, body)) if data.is_none() => data = Some(body),
            _ => {}
        }
        at += 8;
    }

    let name = name?;
    let (runs, resident, real_size) = match data {
        Some(Body::NonResident { runs, real_size }) => (runs, None, real_size.max(name.real_size)),
        Some(Body::Resident(content)) => {
            let size = content.len() as u64;
            (Vec::new(), Some(content), size)
        }
        None => (Vec::new(), None, name.real_size),
    };

    Some(Ghost {
        name: name.name,
        parent: name.parent.record_number,
        real_size,
        created: name.created.0,
        modified: name.modified.0,
        runs,
        resident,
        found,
    })
}

fn attribute_at(buffer: &[u8], at: usize) -> Option<(u32, Body)> {
    let type_code = u32_at(buffer, at)?;
    if type_code != ATTR_FILE_NAME && type_code != ATTR_DATA {
        return None;
    }
    let length = u32_at(buffer, at + 4)? as usize;
    if !(MIN_ATTRIBUTE_BYTES..=MAX_ATTRIBUTE_BYTES).contains(&length)
        || !length.is_multiple_of(8)
        || at.checked_add(length)? > buffer.len()
    {
        return None;
    }
    let name_length = *buffer.get(at + 9)? as usize;
    if type_code == ATTR_DATA && name_length != 0 {
        return None;
    }

    match buffer.get(at + 8)? {
        0 => {
            let content_length = u32_at(buffer, at + 0x10)? as usize;
            let content_offset = u16_at(buffer, at + 0x14)? as usize;
            if content_offset < MIN_ATTRIBUTE_BYTES
                || content_offset.checked_add(content_length)? > length
                || content_length == 0
            {
                return None;
            }
            let start = at.checked_add(content_offset)?;
            let content = buffer.get(start..start.checked_add(content_length)?)?;
            Some((type_code, Body::Resident(content.to_vec())))
        }
        1 if type_code == ATTR_DATA => {
            let runs_offset = u16_at(buffer, at + 0x20)? as usize;
            if runs_offset < MIN_NON_RESIDENT_HEADER || runs_offset >= length {
                return None;
            }
            let real_size = u64_at(buffer, at + 0x30)?;
            let start = at.checked_add(runs_offset)?;
            let runs = decode_runlist(buffer.get(start..at.checked_add(length)?)?).ok()?;
            if runs.is_empty() || runs.len() > MAX_RUNS || runs.iter().all(|run| run.lcn.is_none())
            {
                return None;
            }
            Some((type_code, Body::NonResident { runs, real_size }))
        }
        _ => None,
    }
}

fn plausible_name(name: &FileName) -> bool {
    if name.namespace > 3 || name.name.is_empty() || name.name.chars().count() > MAX_NAME_CHARS {
        return false;
    }
    if name.name.chars().any(|c| c < ' ' || matches!(c, '/' | ':' | '*' | '?' | '"' | '<' | '>')) {
        return false;
    }
    let stamped =
        |t: u64| t == 0 || (FIRST_PLAUSIBLE_FILETIME..LAST_PLAUSIBLE_FILETIME).contains(&t);
    stamped(name.created.0) && stamped(name.modified.0)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREATED: u64 = 133_700_000_000_000_000;

    fn file_name_attribute(parent: u64, name: &str, real_size: u64) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut content = vec![0u8; 0x42 + units.len()];
        content[0x00..0x08].copy_from_slice(&((1u64 << 48) | parent).to_le_bytes());
        content[0x08..0x10].copy_from_slice(&CREATED.to_le_bytes());
        content[0x10..0x18].copy_from_slice(&CREATED.to_le_bytes());
        content[0x28..0x30].copy_from_slice(&real_size.next_multiple_of(4096).to_le_bytes());
        content[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        content[0x40] = name.encode_utf16().count() as u8;
        content[0x41] = 1;
        content[0x42..].copy_from_slice(&units);
        resident(ATTR_FILE_NAME, &content)
    }

    fn resident(type_code: u32, content: &[u8]) -> Vec<u8> {
        const CONTENT_OFFSET: usize = 0x18;
        let length = (CONTENT_OFFSET + content.len()).next_multiple_of(8);
        let mut a = vec![0u8; length];
        a[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
        a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&(CONTENT_OFFSET as u16).to_le_bytes());
        a[CONTENT_OFFSET..CONTENT_OFFSET + content.len()].copy_from_slice(content);
        a
    }

    fn non_resident_data(lcn: u64, clusters: u64, real_size: u64) -> Vec<u8> {
        const RUNS_OFFSET: usize = 0x40;
        let mut runlist = vec![0x44u8];
        runlist.extend_from_slice(&(clusters as u32).to_le_bytes());
        runlist.extend_from_slice(&(lcn as u32).to_le_bytes());
        runlist.push(0);

        let length = (RUNS_OFFSET + runlist.len()).next_multiple_of(8);
        let mut a = vec![0u8; length];
        a[0x00..0x04].copy_from_slice(&ATTR_DATA.to_le_bytes());
        a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
        a[0x08] = 1;
        a[0x18..0x20].copy_from_slice(&(clusters - 1).to_le_bytes());
        a[0x20..0x22].copy_from_slice(&(RUNS_OFFSET as u16).to_le_bytes());
        a[0x28..0x30].copy_from_slice(&(clusters * 4096).to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
        a[RUNS_OFFSET..RUNS_OFFSET + runlist.len()].copy_from_slice(&runlist);
        a
    }

    fn record(used: usize, attributes: &[u8], tail_at: usize, tail: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; RECORD_BYTES];
        r[0x00..0x04].copy_from_slice(b"FILE");
        r[0x04..0x06].copy_from_slice(&0x30u16.to_le_bytes());
        r[0x06..0x08].copy_from_slice(&3u16.to_le_bytes());
        r[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        r[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        r[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
        r[0x18..0x1c].copy_from_slice(&(used as u32).to_le_bytes());
        r[0x1c..0x20].copy_from_slice(&(RECORD_BYTES as u32).to_le_bytes());
        r[0x38..0x38 + attributes.len()].copy_from_slice(attributes);
        r[tail_at..tail_at + tail.len()].copy_from_slice(tail);
        r
    }

    fn ghost_of(name: &str, size: u64, lcn: u64, clusters: u64) -> Vec<u8> {
        let mut tail = file_name_attribute(5, name, size);
        tail.extend(non_resident_data(lcn, clusters, size));
        tail
    }

    fn rcrd_page(images: &[Vec<u8>]) -> Vec<u8> {
        const PAGE: usize = 4096;
        const USN: u16 = 0x0007;
        let mut page = vec![0u8; PAGE];
        page[0x00..0x04].copy_from_slice(b"RCRD");
        page[0x04..0x06].copy_from_slice(&0x28u16.to_le_bytes());
        page[0x06..0x08].copy_from_slice(&9u16.to_le_bytes());
        let mut at = 0x40;
        for image in images {
            page[at..at + image.len()].copy_from_slice(image);
            at += image.len().next_multiple_of(8);
        }
        page[0x28..0x2a].copy_from_slice(&USN.to_le_bytes());
        for sector in 0..8usize {
            let tail = (sector + 1) * 512 - 2;
            let slot = 0x2a + sector * 2;
            let original = [page[tail], page[tail + 1]];
            page[slot..slot + 2].copy_from_slice(&original);
            page[tail..tail + 2].copy_from_slice(&USN.to_le_bytes());
        }
        page
    }

    fn log_of(images: &[Vec<u8>]) -> Vec<u8> {
        let mut log = vec![0u8; 4096];
        log[0x00..0x04].copy_from_slice(b"RSTR");
        for image in images {
            log.extend_from_slice(&rcrd_page(std::slice::from_ref(image)));
        }
        log
    }

    #[test]
    fn a_previous_files_name_and_runlist_survive_in_the_records_tail() {
        let live = file_name_attribute(5, "new.txt", 12);
        let tail = ghost_of("dropper.exe", 9000, 4242, 3);
        let bytes = record(0x38 + live.len(), &live, 0x38 + live.len(), &tail);

        let ghost = in_record_slack(&bytes, 77).expect("the tail still holds the old attributes");
        assert_eq!(ghost.name, "dropper.exe");
        assert_eq!(ghost.parent, 5);
        assert_eq!(ghost.real_size, 9000);
        assert_eq!(ghost.created, CREATED);
        assert_eq!(ghost.runs.len(), 1);
        assert_eq!(ghost.runs[0].lcn, Some(4242));
        assert_eq!(ghost.runs[0].length, 3);
        assert_eq!(ghost.clusters(), 3);
        assert!(ghost.has_bytes());
        assert_eq!(ghost.found, Found::RecordSlack { record: 77 });
        assert_eq!(ghost.found.to_string(), "the unused tail of $MFT record 77");
    }

    #[test]
    fn the_living_occupants_own_attributes_are_never_read_as_a_ghost() {
        let live = ghost_of("live.exe", 4096, 100, 1);
        let bytes = record(0x38 + live.len(), &live, 0x38 + live.len(), &[]);
        assert!(
            in_record_slack(&bytes, 5).is_none(),
            "everything before used_size belongs to the file that is there now"
        );
    }

    #[test]
    fn a_small_files_resident_bytes_survive_whole() {
        let live = file_name_attribute(5, "new.txt", 12);
        let mut tail = file_name_attribute(5, "tiny.exe", 6);
        tail.extend(resident(ATTR_DATA, b"MZtiny"));
        let bytes = record(0x38 + live.len(), &live, 0x38 + live.len(), &tail);

        let ghost = in_record_slack(&bytes, 9).expect("a ghost with resident data");
        assert_eq!(ghost.name, "tiny.exe");
        assert_eq!(ghost.resident.as_deref(), Some(&b"MZtiny"[..]));
        assert_eq!(ghost.real_size, 6);
        assert!(ghost.runs.is_empty());
        assert!(ghost.has_bytes());
    }

    #[test]
    fn a_record_whose_tail_holds_nothing_yields_nothing() {
        let live = file_name_attribute(5, "new.txt", 12);
        let used = 0x38 + live.len();
        assert!(in_record_slack(&record(used, &live, used, &[]), 1).is_none());
        assert!(in_record_slack(&record(used, &live, 900, &[0xff; 64]), 1).is_none());
        assert!(in_record_slack(&vec![0u8; RECORD_BYTES], 1).is_none());
        assert!(in_record_slack(&[], 1).is_none());
    }

    #[test]
    fn a_lying_used_size_is_refused_rather_than_read_past() {
        let live = file_name_attribute(5, "new.txt", 12);
        let tail = ghost_of("dropper.exe", 9000, 4242, 3);
        let mut bytes = record(0x38 + live.len(), &live, 0x38 + live.len(), &tail);
        bytes[0x18..0x1c].copy_from_slice(&(RECORD_BYTES as u32 + 8).to_le_bytes());
        assert!(in_record_slack(&bytes, 1).is_none());
        bytes[0x18..0x1c].copy_from_slice(&4u32.to_le_bytes());
        assert!(in_record_slack(&bytes, 1).is_none());
    }

    #[test]
    fn a_record_image_in_the_log_gives_up_its_name_and_clusters() {
        let attributes = ghost_of("stage2.exe", 40_000, 9000, 10);
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let log = log_of(std::slice::from_ref(&image));

        let ghosts = in_log_file(&log, 64);
        let stage = ghosts.iter().find(|g| g.name == "stage2.exe").expect("the log holds it");
        assert_eq!(stage.real_size, 40_000);
        assert_eq!(stage.runs[0].lcn, Some(9000));
        assert_eq!(stage.clusters(), 10);
        assert_eq!(stage.found, Found::LogFile { offset: 4096 + 0x40 });
        assert!(stage.found.to_string().contains("$LogFile at offset"));
    }

    #[test]
    fn a_page_tail_the_journal_displaced_is_restored_before_the_image_is_read() {
        let long = format!("stage-{}.exe", "x".repeat(200));
        let attributes = ghost_of(&long, 40_000, 9000, 10);
        assert!(
            0x40 + 0x38 + attributes.len() > 0x200,
            "the name must reach past the page's first protected tail for this test to bite"
        );
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let log = log_of(std::slice::from_ref(&image));

        let raw_tail = &log[4096 + 0x1fe..4096 + 0x200];
        assert_eq!(raw_tail, &0x0007u16.to_le_bytes()[..], "on disk the tail holds the page USN");

        let ghosts = in_log_file(&log, 64);
        let stage = ghosts.iter().find(|g| g.name == long).unwrap_or_else(|| {
            panic!("the name crossing the tail must come back whole: {ghosts:?}")
        });
        assert_eq!(stage.real_size, 40_000);
        assert_eq!(stage.clusters(), 10);
    }

    #[test]
    fn a_page_whose_tails_do_not_match_its_usn_is_not_believed() {
        let attributes = ghost_of("stage2.exe", 40_000, 9000, 10);
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let mut log = log_of(std::slice::from_ref(&image));
        log[4096 + 0x1fe] ^= 0xff;
        assert!(
            in_log_file(&log, 64).is_empty(),
            "a torn page's bytes cannot be trusted, so nothing may be read from it"
        );
    }

    #[test]
    fn a_log_with_no_record_images_yields_nothing() {
        assert!(in_log_file(&[], 64).is_empty());
        assert!(in_log_file(&vec![0u8; 8192], 64).is_empty());
        assert!(in_log_file(b"FILE", 64).is_empty());
        assert!(in_log_file(&vec![0xffu8; 4096], 64).is_empty());
        let attributes = ghost_of("bare.exe", 4096, 500, 1);
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let mut bare = vec![0u8; 4096];
        bare.extend_from_slice(&image);
        assert!(
            in_log_file(&bare, 64).is_empty(),
            "an image outside a fixed-up RCRD page has unreliable bytes and is not read"
        );
    }

    #[test]
    fn the_log_sweep_stops_at_its_budget() {
        let attributes = ghost_of("many.exe", 4096, 500, 1);
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let log = log_of(&vec![image; 8]);
        assert_eq!(in_log_file(&log, 3).len(), 3);
        assert!(in_log_file(&log, 64).len() >= 8);
    }

    #[test]
    fn three_images_in_one_page_are_all_read() {
        let attributes = ghost_of("trio.exe", 4096, 500, 1);
        let image = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let mut log = vec![0u8; 4096];
        log[0x00..0x04].copy_from_slice(b"RSTR");
        log.extend_from_slice(&rcrd_page(&vec![image; 3]));
        assert_eq!(in_log_file(&log, 64).len(), 3);
    }

    #[test]
    fn a_name_no_directory_could_hold_is_not_a_ghost() {
        for bad in ["a:b.exe", "a*b.exe", "a?b.exe", "a<b.exe", ""] {
            let live = file_name_attribute(5, "new.txt", 12);
            let mut tail = file_name_attribute(5, bad, 4096);
            tail.extend(non_resident_data(4242, 1, 4096));
            let used = 0x38 + live.len();
            let bytes = record(used, &live, used, &tail);
            assert!(in_record_slack(&bytes, 1).is_none(), "{bad:?} must not parse as a name");
        }
    }

    #[test]
    fn a_timestamp_no_windows_machine_could_have_written_is_not_a_ghost() {
        let live = file_name_attribute(5, "new.txt", 12);
        let mut tail = file_name_attribute(5, "dropper.exe", 4096);
        tail[0x18 + 0x08..0x18 + 0x10].copy_from_slice(&1u64.to_le_bytes());
        tail.extend(non_resident_data(4242, 1, 4096));
        let used = 0x38 + live.len();
        assert!(in_record_slack(&record(used, &live, used, &tail), 1).is_none());
    }

    #[test]
    fn a_runlist_that_names_no_cluster_is_refused() {
        let live = file_name_attribute(5, "new.txt", 12);
        let mut tail = file_name_attribute(5, "sparse.exe", 4096);
        let mut sparse = non_resident_data(4242, 1, 4096);
        let runs_at = 0x40;
        sparse[runs_at] = 0x01;
        sparse[runs_at + 1] = 1;
        sparse[runs_at + 2] = 0;
        tail.extend(sparse);
        let used = 0x38 + live.len();
        let ghost = in_record_slack(&record(used, &live, used, &tail), 1);
        assert!(ghost.is_some_and(|g| g.runs.is_empty() && !g.has_bytes()));
    }

    #[test]
    fn every_byte_offset_into_a_record_is_survivable() {
        let attributes = ghost_of("dropper.exe", 9000, 4242, 3);
        let full = record(0x38 + attributes.len(), &attributes, RECORD_BYTES, &[]);
        let log = log_of(std::slice::from_ref(&full));
        for cut in 0..full.len() {
            let _ = in_record_slack(&full[..cut], 1);
            let _ = in_log_file(&log[..4096 + cut], 8);
        }
        for byte in 0..full.len() {
            let mut damaged = full.clone();
            damaged[byte] ^= 0xff;
            let _ = in_record_slack(&damaged, 1);
            let _ = in_log_file(&log_of(std::slice::from_ref(&damaged)), 8);
        }
    }
}

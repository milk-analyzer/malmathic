use std::collections::HashMap;
use std::io::{BufWriter, Read, Seek, Write};

use ntfs_core::usn::UsnReason;

const ROOT_RECORD: u64 = 5;
const NAMESPACE_DOS: u8 = 2;
const ATTR_FILE_NAME: u32 = 0x30;
const MAX_PATH_DEPTH: usize = 64;

fn resolve_directory<R: Read + Seek>(
    volume: &mm_raw::Volume<R>,
    record: u64,
    expected_sequence: u16,
    cache: &mut HashMap<u64, Option<String>>,
    depth: usize,
) -> Option<String> {
    if record == ROOT_RECORD {
        return Some("\\".to_string());
    }
    if depth >= MAX_PATH_DEPTH {
        return None;
    }
    let bytes = volume.fs().read_record(record).ok()?;
    let header = ntfs_core::MftRecordHeader::parse(&bytes).ok()?;
    if &header.signature != b"FILE" || !header.is_base_record() {
        return None;
    }
    if expected_sequence != 0 && header.sequence_number != expected_sequence {
        return None;
    }
    if !header.is_in_use() || !header.is_directory() {
        return None;
    }
    if let Some(hit) = cache.get(&record) {
        return hit.clone();
    }
    let attributes =
        ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize).ok()?;
    let mut name: Option<String> = None;
    let mut parent: Option<(u64, u16)> = None;
    let mut best_namespace = u8::MAX;
    for attribute in &attributes {
        if attribute.type_code != ATTR_FILE_NAME {
            continue;
        }
        let Some(content) = attribute.resident_content(&bytes) else { continue };
        let Ok(file_name) = ntfs_core::FileName::parse(content) else { continue };
        if file_name.namespace != NAMESPACE_DOS && file_name.namespace < best_namespace {
            best_namespace = file_name.namespace;
            name = Some(file_name.name.clone());
            parent = Some((file_name.parent.record_number, file_name.parent.sequence));
        } else if name.is_none() {
            name = Some(file_name.name.clone());
            parent = Some((file_name.parent.record_number, file_name.parent.sequence));
        }
    }
    let name = name?;
    let (parent_record, parent_sequence) = parent?;
    let resolved = resolve_directory(volume, parent_record, parent_sequence, cache, depth + 1)
        .map(|p| if p == "\\" { format!("\\{name}") } else { format!("{p}\\{name}") });
    cache.insert(record, resolved.clone());
    resolved
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (image, out) = match args.as_slice() {
        [i, o] => (i.clone(), o.clone()),
        _ => {
            eprintln!("usage: usndump <image> <out.tsv>");
            std::process::exit(2);
        }
    };
    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(&image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(&image), *partition) {
            if volume.is_windows_install() {
                chosen = Some(volume);
                break;
            }
            if chosen.is_none() {
                chosen = Some(volume);
            }
        }
    }
    let Some(volume) = chosen else {
        eprintln!("no readable NTFS in {image}");
        std::process::exit(1);
    };

    let journal = mm_raw::usn::read_journal(&volume);
    eprintln!(
        "records={} verdict={:?} window={:?}",
        journal.records.len(),
        journal.verdict(),
        journal.window()
    );

    let file = std::fs::File::create(&out).expect("creating the output");
    let mut w = BufWriter::with_capacity(1 << 20, file);
    let mut cache: HashMap<u64, Option<String>> = HashMap::new();
    let interesting = UsnReason::FILE_CREATE
        | UsnReason::FILE_DELETE
        | UsnReason::RENAME_NEW_NAME
        | UsnReason::RENAME_OLD_NAME;
    let mut emitted = 0u64;
    for record in &journal.records {
        if !record.reason.intersects(interesting) {
            continue;
        }
        let directory = resolve_directory(
            &volume,
            record.parent_mft_entry,
            record.parent_mft_sequence,
            &mut cache,
            0,
        );
        let full = match &directory {
            Some(d) if d == "\\" => format!("\\{}", record.filename),
            Some(d) => format!("{d}\\{}", record.filename),
            None => "-".to_string(),
        };
        let _ = writeln!(
            w,
            "{}\t0x{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            record.timestamp.format("%Y-%m-%dT%H:%M:%S%.9fZ"),
            record.reason.bits(),
            record.reason,
            record.mft_entry,
            record.mft_sequence,
            record.parent_mft_entry,
            record.parent_mft_sequence,
            full,
            record.filename,
        );
        emitted += 1;
    }
    w.flush().unwrap();
    eprintln!("{emitted} rows emitted, {} directories cached", cache.len());
}

#![cfg(test)]

use std::io::Cursor;

use mm_raw::{Fate, Slack, Volume};

use crate::testimage::{Builder, IndexLayout, Presence, Times, ROOT_RECORD};

const LONG_NAME: &str = "a-very-long-installer-name-that-leaves-a-large-hole-behind-it.tmp";

const SAMPLE: &str = "server.exe";
const SAMPLE_BYTES: usize = 45_056;

const CREATED: u64 = Times::at(1_778_784_843, 1_234_567);

fn volume(presence: Presence) -> (Volume<Cursor<Vec<u8>>>, u64) {
    let mut builder = Builder::with_records(512);
    let temp = windows(&mut builder);

    let long = builder.file(temp, LONG_NAME, &vec![0u8; 4096], Presence::Live);
    builder.set_file_name_times(long, Times::all_at(CREATED));
    let keep = builder.resident_file(temp, "keep.dll", b"MZ still here", Presence::Live);
    builder.set_file_name_times(keep, Times::all_at(CREATED));

    builder.delete_index_entry(temp, LONG_NAME);

    let sample = builder.deleted_index_entry(temp, SAMPLE, &vec![0x90u8; SAMPLE_BYTES], presence);
    builder.set_file_name_times(sample, Times::all_at(CREATED));
    if !matches!(presence, Presence::Deleted) {
        builder.set_sequence(sample, 2);
    }

    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic")
        .expect("the synthetic volume opens");
    (volume, temp)
}

fn windows(builder: &mut Builder) -> u64 {
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    let kernel = builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let config = builder.directory(system32, "config");
    let system = builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);
    let temp = builder.directories(ROOT_RECORD, r"Windows\Temp");
    for record in [system32, config, temp, kernel, system] {
        builder.set_file_name_times(record, Times::all_at(CREATED));
    }
    let windows = builder.directory(ROOT_RECORD, "Windows");
    builder.set_file_name_times(windows, Times::all_at(CREATED));
    temp
}

fn swept(volume: &Volume<Cursor<Vec<u8>>>, temp: u64) -> mm_raw::Recovered {
    let bounds = volume.slack_bounds();
    volume.deleted_index_entries(temp, &bounds)
}

#[test]
fn the_validator_accepts_every_live_entry_of_the_fixture() {
    let (volume, temp) = volume(Presence::Deleted);
    let found = swept(&volume, temp);
    assert_eq!(
        found.stats.live_accepted, found.stats.live_seen,
        "refused a live entry the fixture wrote: {:?}",
        found.refused_live
    );
    assert!(found.stats.live_seen > 0, "the fixture has no live entries to check against");
}

#[test]
fn the_deleted_sample_comes_back_with_its_name_size_and_true_creation_time() {
    let (volume, temp) = volume(Presence::Deleted);
    let found = swept(&volume, temp);

    let entry = found
        .entries
        .iter()
        .find(|e| e.name == SAMPLE)
        .unwrap_or_else(|| panic!("{SAMPLE} was not recovered: {:?}", found.entries));

    assert_eq!(entry.real_size, SAMPLE_BYTES as u64, "the exact byte length is the prize");
    assert_eq!(entry.created, CREATED, "the $FILE_NAME creation time SetFileTime cannot reach");
    assert_eq!(entry.parent_record, temp, "the entry names the directory it came out of");
    assert!(!entry.is_directory());
    assert!(matches!(entry.found_in, Slack::IndexRoot | Slack::Record));
}

#[test]
fn the_live_children_are_not_reported_as_deleted() {
    let (volume, temp) = volume(Presence::Deleted);
    let found = swept(&volume, temp);
    assert!(
        !found.entries.iter().any(|e| e.name == "keep.dll"),
        "reported a live child as deleted: {:?}",
        found.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    let mut names: Vec<String> =
        volume.list_directory_entries(r"\Windows\Temp").into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec!["keep.dll".to_string()]);
}

#[test]
fn a_record_that_is_merely_free_is_said_to_be_free() {
    let (volume, temp) = volume(Presence::Deleted);
    let entry = swept(&volume, temp).entries.into_iter().find(|e| e.name == SAMPLE).expect(SAMPLE);
    assert_eq!(volume.record_fate(entry.record, entry.sequence), Fate::Free);
}

#[test]
fn a_reallocated_record_is_named_rather_than_inferred() {
    let (volume, temp) = volume(Presence::RecordReallocatedTo("something-else.log"));
    let entry = swept(&volume, temp).entries.into_iter().find(|e| e.name == SAMPLE).expect(SAMPLE);

    let fate = volume.record_fate(entry.record, entry.sequence);
    assert_eq!(
        fate,
        Fate::Reallocated { sequence: 2, to: Some("something-else.log".to_string()) },
        "the sequence in the index entry and the one in the record settle this"
    );
    assert!(fate.is_gone());
    assert!(fate.to_string().contains("REALLOCATED"));
    assert_eq!(entry.real_size, SAMPLE_BYTES as u64);
    assert_eq!(entry.created, CREATED);
}

#[test]
fn a_directory_that_lost_nothing_yields_nothing() {
    let mut builder = Builder::with_records(512);
    let temp = windows(&mut builder);
    for name in ["one.dll", "two.dll", "three.dll", LONG_NAME] {
        let record = builder.resident_file(temp, name, b"MZ", Presence::Live);
        builder.set_file_name_times(record, Times::all_at(CREATED));
    }
    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic")
        .expect("the synthetic volume opens");

    let bounds = volume.slack_bounds();
    for record in 0..bounds.records {
        let found = volume.deleted_index_entries(record, &bounds);
        assert!(
            found.entries.is_empty(),
            "record {record} invented {:?} out of a volume nothing was deleted from",
            found.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert!(
            found.refused_live.is_empty(),
            "record {record} ({:?}, children {:?}) refused a live entry: {:?}",
            volume.record_identity(record).map(|i| i.name),
            volume
                .list_directory_entries_of_record(record)
                .map(|c| c.into_iter().map(|e| e.name).collect::<Vec<_>>()),
            found.refused_live
        );
    }
}

const BITMAP_RECORD: u64 = 6;

fn volume_with_an_abandoned_page() -> (Volume<Cursor<Vec<u8>>>, Vec<String>) {
    let mut builder = Builder::with_records(512);
    let temp = windows(&mut builder);

    let store = builder.directory(temp, "store");
    builder.set_file_name_times(store, Times::all_at(CREATED));
    builder.spill_index(store, IndexLayout::LargeInBase);
    let mut names = Vec::new();
    for i in 0..8 {
        let name = format!("payload{i}.exe");
        let record = builder.resident_file(store, &name, b"MZ", Presence::Live);
        builder.set_file_name_times(record, Times::all_at(CREATED));
        if i % 2 == 0 {
            names.push(name);
        }
    }
    builder.abandon_index_page(store);

    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic")
        .expect("the synthetic volume opens");
    names.sort();
    (volume, names)
}

#[test]
fn an_index_page_abandoned_in_free_space_is_carved() {
    let (volume, names) = volume_with_an_abandoned_page();
    let bitmap = volume.read_record_capped(BITMAP_RECORD, 64 * 1024 * 1024).expect("$Bitmap");
    let bounds = volume.slack_bounds();

    let found = volume.carved_index_entries(&bitmap, &bounds, u64::MAX);
    assert!(found.stopped.is_none(), "the scan stopped early: {:?}", found.stopped);
    assert!(found.buffers > 0, "no INDX page was found in free space");
    assert_eq!(found.fixed_up, found.buffers, "a page failed its update-sequence array");
    assert_eq!(found.disagreeing_pages, 0);

    let mut carved: Vec<String> = found
        .entries
        .iter()
        .filter(|e| e.name.starts_with("payload"))
        .map(|e| e.name.clone())
        .collect();
    carved.sort();
    carved.dedup();
    assert_eq!(carved, names, "the abandoned page did not give up its entries");

    let parents: Vec<u64> = found.entries.iter().map(|e| e.parent_record).collect();
    assert!(parents.windows(2).all(|w| w[0] == w[1]), "one page named two parents");
}

#[test]
fn free_space_with_no_abandoned_page_yields_nothing() {
    let mut builder = Builder::with_records(512);
    let temp = windows(&mut builder);
    let store = builder.directory(temp, "store");
    builder.set_file_name_times(store, Times::all_at(CREATED));
    builder.spill_index(store, IndexLayout::LargeInBase);
    for i in 0..8 {
        let record =
            builder.resident_file(store, &format!("payload{i}.exe"), b"MZ", Presence::Live);
        builder.set_file_name_times(record, Times::all_at(CREATED));
    }
    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic")
        .expect("the synthetic volume opens");

    let bitmap = volume.read_record_capped(BITMAP_RECORD, 64 * 1024 * 1024).expect("$Bitmap");
    let bounds = volume.slack_bounds();
    let found = volume.carved_index_entries(&bitmap, &bounds, u64::MAX);
    assert!(
        found.entries.is_empty(),
        "carved {:?} out of the free space of a volume that abandoned nothing",
        found.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

#[test]
fn a_scan_that_hits_its_budget_says_so() {
    let (volume, _) = volume_with_an_abandoned_page();
    let bitmap = volume.read_record_capped(BITMAP_RECORD, 64 * 1024 * 1024).expect("$Bitmap");
    let bounds = volume.slack_bounds();
    let found = volume.carved_index_entries(&bitmap, &bounds, 8);
    assert!(found.scanned_clusters <= 8);
    assert!(found.stopped.is_some(), "a truncated scan reported itself as complete");
}

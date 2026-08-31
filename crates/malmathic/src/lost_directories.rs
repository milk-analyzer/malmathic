#![cfg(test)]

use std::io::{Read, Seek};

use mm_harvest::filesystem::{self, LostReason};
use mm_raw::Volume;

use crate::hostile_index::metered;
use crate::testimage::{Builder, IndexLayout, Presence, ATTR_FILE_NAME, ROOT_RECORD};

const CHILDREN: usize = 12;

const MAGICIAN: &str = "\\program files (x86)\\samsung\\samsung magician";
const CONTROL: &str = "\\program files (x86)\\steam\\steam.exe";

struct Machine {
    magician: u64,
    steam: u64,
}

fn machine_with_a_spilled_name() -> (Builder, Machine) {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let config = builder.directory(system32, "config");
    builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);

    let samsung = builder.directories(ROOT_RECORD, "Program Files (x86)\\Samsung");
    let magician = builder.directory(samsung, "Samsung Magician");
    for i in 0..CHILDREN {
        builder.resident_file(
            magician,
            &format!("tool{i}.exe"),
            b"MZ a Samsung utility",
            Presence::Live,
        );
    }
    let steam = builder.directories(ROOT_RECORD, "Program Files (x86)\\Steam");
    let steam_exe = builder.resident_file(steam, "steam.exe", b"MZ steam", Presence::Live);

    builder.spill_index(magician, IndexLayout::AllocationInExtension);
    builder.spill_file_name(magician);
    (builder, Machine { magician, steam: steam_exe })
}

fn spilled_volume() -> (Volume<impl Read + Seek>, Machine) {
    let (builder, machine) = machine_with_a_spilled_name();
    (builder.open(), machine)
}

fn walk<R: Read + Seek>(volume: &Volume<R>) -> (Vec<String>, filesystem::WalkReport) {
    let mut keys = Vec::new();
    let report = filesystem::enumerate_with_progress(
        volume,
        &mut |path, _facts| keys.push(path.key().to_string()),
        &mut |_, _| {},
    )
    .expect("the synthetic volume walks");
    keys.sort();
    (keys, report)
}

fn under_magician(keys: &[String]) -> Vec<&String> {
    keys.iter().filter(|k| k.contains("samsung magician")).collect()
}

#[test]
fn the_bug_is_the_absence_of_the_follow() {
    let (mut builder, machine) = machine_with_a_spilled_name();
    builder.misdirect_file_name(machine.magician, machine.steam);
    let volume = builder.open();

    assert_eq!(volume.resolve(MAGICIAN), Some(machine.magician));
    assert_eq!(volume.list_directory_entries(MAGICIAN).len(), CHILDREN);

    let (keys, report) = walk(&volume);
    assert!(keys.iter().any(|k| k == CONTROL), "the control walks");
    assert!(
        under_magician(&keys).is_empty(),
        "the walk emits nothing under the lost directory: {:?}",
        under_magician(&keys)
    );
    assert_eq!(report.stats.unresolved, CHILDREN as u64);
    assert_eq!(report.stats.unresolved_directories, 1, "one place, not twelve");
    assert_eq!(report.stats.names_recovered, 0, "nothing was recovered, and nothing claims to be");
}

#[test]
fn a_directory_whose_name_moved_is_now_walked() {
    let (volume, _) = spilled_volume();
    let (keys, _) = walk(&volume);

    assert!(keys.iter().any(|k| k == CONTROL), "the control still walks");
    let mut found = under_magician(&keys).into_iter().cloned().collect::<Vec<_>>();
    found.sort();
    let mut want: Vec<String> = (0..CHILDREN).map(|i| format!("{MAGICIAN}\\tool{i}.exe")).collect();
    want.sort();
    assert_eq!(found, want, "every child, at its real path");
}

#[test]
fn the_walk_and_the_index_agree_on_the_spilled_directory() {
    let (volume, _) = spilled_volume();
    let (keys, _) = walk(&volume);

    for entry in volume.list_directory_entries(MAGICIAN) {
        let key = format!("{MAGICIAN}\\{}", entry.name.to_lowercase());
        assert!(keys.contains(&key), "the index lists {key} and the walk did not emit it");
    }
    for key in under_magician(&keys) {
        assert!(volume.resolve(key).is_some(), "the walk emitted {key} and it resolves nowhere");
    }
}

#[test]
fn the_recovery_is_counted_and_nothing_is_reported_lost() {
    let (volume, _) = spilled_volume();
    let (_, report) = walk(&volume);

    assert_eq!(report.stats.names_recovered, 1, "one name came out of an extension record");
    assert_eq!(report.stats.unresolved, 0);
    assert_eq!(report.stats.unresolved_directories, 0);
    assert_eq!(report.stats.unparsable, 0, "the record that would not parse now parses");
    assert!(report.lost.is_empty(), "nothing is lost: {:?}", report.lost);
    assert!(
        report.stats.extension_records >= 1,
        "the extension record is still skipped as a record, and still counted"
    );
}

#[test]
fn the_run_states_how_many_records_could_still_be_hiding_an_attribute() {
    let (volume, _) = spilled_volume();
    let (_, report) = walk(&volume);

    assert_eq!(
        report.stats.attribute_lists_seen, 1,
        "exactly one record on this volume spilled anything, and the run says so"
    );

    let mut plain = Builder::new();
    let system32 = plain.directories(ROOT_RECORD, "Windows\\System32");
    plain.resident_file(system32, "ntoskrnl.exe", b"MZ", Presence::Live);
    let config = plain.directory(system32, "config");
    plain.resident_file(config, "SYSTEM", b"regf", Presence::Live);
    let (_, plain_report) = walk(&plain.open());
    assert_eq!(plain_report.stats.attribute_lists_seen, 0);
    assert_eq!(plain_report.stats.names_recovered, 0);
}

#[test]
fn a_name_the_list_points_at_another_file_is_refused_rather_than_adopted() {
    let (mut builder, machine) = machine_with_a_spilled_name();
    builder.misdirect_file_name(machine.magician, machine.steam);
    let volume = builder.open();
    let (keys, report) = walk(&volume);

    assert_eq!(
        keys.iter().filter(|k| k.ends_with("steam.exe")).collect::<Vec<_>>(),
        vec![&CONTROL.to_string()],
        "`steam.exe` is where it is, once, and nowhere else"
    );
    assert!(
        !keys.iter().any(|k| k.contains("samsung magician")),
        "and the directory stayed nameless rather than borrowing one"
    );
    assert_eq!(report.stats.names_recovered, 0);

    let lost = report.lost.first().expect("the walk names where it lost them");
    assert_eq!(lost.parent as u64, machine.magician);
    assert_eq!(lost.broke_at as u64, machine.magician, "the break is the directory itself");
    assert_eq!(lost.files_lost, CHILDREN as u64);
    assert_eq!(lost.reason, LostReason::NameNotRecovered);
    assert!(lost.reason.describe().contains("$ATTRIBUTE_LIST"));
    assert_eq!(lost.broken_name, None);
}

#[test]
fn a_name_the_list_points_into_nowhere_leaves_the_record_unnamed() {
    let (mut builder, machine) = machine_with_a_spilled_name();
    builder.misdirect_file_name(machine.magician, 0x0000_FFFF_FFFF_FFF0);
    let volume = builder.open();

    let (keys, report) = walk(&volume);
    assert!(keys.iter().any(|k| k == CONTROL), "the rest of the volume is untouched");
    assert!(under_magician(&keys).is_empty());
    assert_eq!(report.stats.names_recovered, 0);
    assert_eq!(report.stats.unresolved_directories, 1);
    assert_eq!(report.lost[0].reason, LostReason::NameNotRecovered);
}

#[test]
fn a_spilled_name_and_a_condemned_record_do_not_share_a_reason() {
    let (mut builder, machine) = machine_with_a_spilled_name();
    builder.misdirect_file_name(machine.magician, machine.steam);
    let spilled = builder.open();
    let (_, spilled_report) = walk(&spilled);
    assert_eq!(spilled_report.lost[0].reason, LostReason::NameNotRecovered);

    let (builder, machine) = machine_with_a_spilled_name();
    let mut image = builder.bytes();
    let at = record_offset(&image, machine.magician);
    image[at..at + 4].copy_from_slice(b"BAAD");
    let condemned = Volume::open(std::io::Cursor::new(image), "condemned").expect("it opens");
    let (_, condemned_report) = walk(&condemned);
    assert_eq!(condemned_report.lost[0].reason, LostReason::Condemned);
    assert_eq!(condemned_report.lost[0].files_lost, CHILDREN as u64);
    assert_ne!(
        LostReason::Condemned.describe(),
        LostReason::NameNotRecovered.describe(),
        "two findings, two sentences"
    );
}

fn record_offset(image: &[u8], record: u64) -> usize {
    let sector = u16::from_le_bytes([image[0x0B], image[0x0C]]) as usize;
    let cluster = sector * image[0x0D] as usize;
    let mft_lcn = u64::from_le_bytes(image[0x30..0x38].try_into().unwrap());
    mft_lcn as usize * cluster + record as usize * crate::testimage::RECORD
}

#[test]
fn a_padded_attribute_list_costs_a_bounded_number_of_reads() {
    const MAX_EXTENSION_RECORDS: usize = 16;
    const PADDING: usize = 100;

    fn cost(padding: &[u64]) -> (usize, filesystem::WalkReport) {
        let (mut builder, machine) = machine_with_a_spilled_name();
        builder.spill_attribute_list(machine.magician);
        builder.pad_attribute_list_of(machine.magician, ATTR_FILE_NAME, padding);
        let (volume, meter) = metered(builder);
        let before = meter.snapshot();
        let (_, report) = walk(&volume);
        (meter.snapshot().since(&before).reads, report)
    }

    let targets: Vec<u64> = (0..PADDING as u64).map(|i| 64 + i).collect();
    let (bare, bare_report) = cost(&[]);
    let started = std::time::Instant::now();
    let (padded, padded_report) = cost(&targets);
    let elapsed = started.elapsed();

    const { assert!(PADDING > MAX_EXTENSION_RECORDS, "the ceiling has to be what stops it") };
    assert!(
        padded <= bare + MAX_EXTENSION_RECORDS,
        "{PADDING} extra entries cost {} extra reads against a ceiling of          {MAX_EXTENSION_RECORDS}",
        padded - bare
    );
    assert!(elapsed < std::time::Duration::from_secs(5), "took {elapsed:?}");
    assert_eq!(bare_report.stats.names_recovered, 1);
    assert_eq!(padded_report.stats.names_recovered, 1, "the padding cost the directory its name");
    assert!(padded_report.lost.is_empty());
}

#[test]
fn a_record_named_many_times_is_read_once() {
    let (mut builder, machine) = machine_with_a_spilled_name();
    builder.spill_attribute_list(machine.magician);
    let targets = vec![machine.steam; 100];
    builder.pad_attribute_list_of(machine.magician, ATTR_FILE_NAME, &targets);

    let (volume, meter) = metered(builder);
    let before = meter.snapshot();
    let (keys, report) = walk(&volume);
    let cost = meter.snapshot().since(&before);

    let (bare_volume, _) = {
        let (mut b, m) = machine_with_a_spilled_name();
        b.spill_attribute_list(m.magician);
        let (v, meter) = metered(b);
        let before = meter.snapshot();
        let _ = walk(&v);
        (meter.snapshot().since(&before).reads, ())
    };
    assert!(
        cost.reads <= bare_volume + 1,
        "one record named a hundred times cost {} reads against {bare_volume} unpadded",
        cost.reads
    );
    assert_eq!(report.stats.names_recovered, 1);
    assert_eq!(
        keys.iter().filter(|k| k.ends_with("steam.exe")).count(),
        1,
        "`steam.exe` is where it is, once"
    );
}

#[test]
fn never_allocated_records_are_counted_apart_from_damaged_ones() {
    let mut builder = Builder::with_records(512);
    let dir = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(dir, "ntoskrnl.exe", b"MZ", Presence::Live);
    let volume = builder.open();

    let (_, report) = walk(&volume);
    assert_eq!(
        report.stats.unparsable, 0,
        "nothing on this volume is damaged, so the damage counter must read zero"
    );
    assert!(
        report.stats.records_skipped > 100,
        "and the slack must be counted somewhere: {} skipped",
        report.stats.records_skipped
    );
}

#[test]
fn a_spilled_alternate_stream_is_seen_by_the_walk() {
    for spill in [false, true] {
        let mut builder = Builder::new();
        let downloads = builder.directories(ROOT_RECORD, r"Users\bob\Downloads");
        let installer = builder.resident_file(downloads, "setup.exe", b"MZ", Presence::Live);
        builder.alternate_stream(installer, "Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n");
        if spill {
            builder.spill_named_stream(installer, "Zone.Identifier");
        }
        let volume = builder.open();

        let mut ads = None;
        let mut named = false;
        filesystem::enumerate(&volume, &mut |path, facts| {
            if path.key().ends_with("setup.exe") {
                named = true;
                ads = Some(facts.has_ads);
            }
        })
        .expect("the walk completes");

        assert!(named, "spill={spill}: the walk never emitted the file at all");
        assert_eq!(ads, Some(true), "spill={spill}: the walk did not see the alternate stream");
    }
}

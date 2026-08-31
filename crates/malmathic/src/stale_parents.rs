#![cfg(test)]

use std::io::{Read, Seek};

use mm_harvest::filesystem::{self, LostReason};
use mm_raw::Volume;

use crate::testimage::{Builder, IndexLayout, Presence, ROOT_RECORD};

const ORPHANS: usize = 6;

const NOW: u16 = 5;
const THEN: u16 = 4;

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

fn windows(builder: &mut Builder) {
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let config = builder.directory(system32, "config");
    builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);
}

fn chrome_with_a_leftover() -> (Builder, u64, u64) {
    let mut builder = Builder::new();
    windows(&mut builder);

    let locales = builder.directories(
        ROOT_RECORD,
        "Program Files\\Google\\Chrome\\Application\\150.0.7871.187\\Locales",
    );
    let pak = builder.resident_file(locales, "sw_NEUTER.pak", b"pak data", Presence::Live);
    builder.set_sequence(pak, NOW);

    let orphaned = builder.directory(pak, "Locales");
    for i in 0..ORPHANS {
        builder.resident_file(orphaned, &format!("{i}_NEUTER.pak"), b"old pak", Presence::Live);
    }
    (builder, pak, orphaned)
}

#[test]
fn a_leftover_naming_a_reused_record_is_reported_as_stale() {
    let (mut builder, pak, orphaned) = chrome_with_a_leftover();
    builder.set_parent_sequence(orphaned, THEN);
    let volume = builder.open();

    let (keys, report) = walk(&volume);
    assert!(
        keys.iter().any(|k| k.ends_with("locales\\sw_neuter.pak")),
        "the live pak file still walks"
    );
    assert_eq!(report.stats.unresolved, ORPHANS as u64);
    assert_eq!(report.stats.unresolved_directories, 1, "one place, not six");

    let lost = report.lost.first().expect("the run names the place it lost");
    assert_eq!(lost.parent, orphaned as u32);
    assert_eq!(lost.parent_sequence, 1, "the leftover's own record is on its first incarnation");
    assert_eq!(lost.broke_at, pak as u32);
    assert_eq!(lost.broken_name.as_deref(), Some("sw_NEUTER.pak"));
    assert_eq!(lost.reason, LostReason::StaleParentReference);
    assert_eq!(lost.stale, Some((THEN, NOW)), "the run states both sequence numbers");
    assert!(
        lost.reason.describe().contains("reallocated"),
        "the reason has to read as a fact about the disk: {}",
        lost.reason.describe()
    );
}

#[test]
fn a_current_reference_onto_a_file_is_still_reported_as_not_a_directory() {
    let (mut builder, pak, _orphaned) = chrome_with_a_leftover();
    let volume = {
        builder.set_sequence(pak, 1);
        builder.open()
    };

    let (_keys, report) = walk(&volume);
    let lost = report.lost.first().expect("the run names the place it lost");
    assert_eq!(lost.reason, LostReason::NotADirectory);
    assert_eq!(lost.stale, None);
}

#[test]
fn the_run_says_whether_the_names_it_lost_belonged_to_deleted_records() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let locales = builder.directories(
        ROOT_RECORD,
        "Program Files\\Google\\Chrome\\Application\\150.0.7871.187\\Locales",
    );
    let pak = builder.resident_file(locales, "sw_NEUTER.pak", b"pak data", Presence::Live);
    builder.set_sequence(pak, NOW);

    let orphaned = builder.directory(pak, "Locales");
    builder.set_parent_sequence(orphaned, THEN);
    for i in 0..ORPHANS {
        builder.resident_file(orphaned, &format!("{i}_NEUTER.pak"), b"old", Presence::Deleted);
    }
    builder.resident_file(orphaned, "still_here.exe", b"MZ", Presence::Live);

    let (_keys, report) = walk(&builder.open());
    assert_eq!(report.stats.unresolved_links, ORPHANS as u64 + 1);
    assert_eq!(
        report.stats.unresolved_deleted, ORPHANS as u64,
        "the deleted remnants are counted apart from the live file"
    );
}

fn temp_with_a_leftover(leftover_sequence: u16) -> (Builder, u64) {
    let mut builder = Builder::new();
    windows(&mut builder);

    let windows_dir = builder.directories(ROOT_RECORD, "Windows");
    let temp = builder.directory(windows_dir, "Temp");
    builder.set_sequence(temp, 3);
    let live = builder.resident_file(temp, "live.exe", b"MZ current", Presence::Live);
    builder.set_parent_sequence(live, 3);

    let leftover = builder.resident_file(temp, "phantom.exe", b"MZ from before", Presence::Live);
    builder.set_parent_sequence(leftover, leftover_sequence);
    (builder, leftover)
}

#[test]
fn without_the_sequence_the_walk_emits_a_path_the_file_was_never_at() {
    let (builder, _leftover) = temp_with_a_leftover(3);
    let (keys, report) = walk(&builder.open());

    assert!(keys.iter().any(|k| k == "\\windows\\temp\\phantom.exe"));
    assert_eq!(report.stats.unresolved, 0, "the walk is perfectly happy");
    assert_eq!(report.stats.stale_parent_links, 0, "and it has nothing to report");
}

#[test]
fn a_stale_reference_onto_a_live_directory_is_refused() {
    let (builder, _leftover) = temp_with_a_leftover(2);
    let (keys, report) = walk(&builder.open());

    assert!(
        keys.iter().any(|k| k == "\\windows\\temp\\live.exe"),
        "the directory's own live file is untouched"
    );
    assert!(
        !keys.iter().any(|k| k == "\\windows\\temp\\phantom.exe"),
        "a file was placed in a directory that did not exist when its name was written: {keys:?}"
    );
    assert_eq!(report.stats.unresolved, 1);
    assert_eq!(report.stats.stale_parent_links, 1);
    assert!(report.stats.sequence_check_applied);

    let lost = report.lost.first().expect("the run names the place it lost");
    assert_eq!(lost.reason, LostReason::StaleParentReference);
    assert_eq!(lost.stale, Some((2, 3)));
    assert_eq!(
        lost.reached, "\\Windows",
        "the run says where the record that took the number now lives"
    );
}

#[test]
fn the_refusal_survives_the_path_cache() {
    let (builder, leftover) = temp_with_a_leftover(2);
    let volume = builder.open();
    let (keys, _report) = walk(&volume);
    assert!(leftover > 0);
    assert!(!keys.iter().any(|k| k == "\\windows\\temp\\phantom.exe"));
    assert!(keys.iter().any(|k| k == "\\windows\\temp\\live.exe"));
}

#[test]
fn a_file_whose_other_name_is_current_is_still_walked() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    let store = builder.directories(ROOT_RECORD, "Windows\\WinSxS\\amd64_driver");
    builder.set_sequence(store, 7);

    let driver = builder.resident_file(system32, "driver.sys", b"MZ a driver", Presence::Live);
    builder.add_link(driver, store, 6, "driver.sys");
    let volume = builder.open();

    let (keys, report) = walk(&volume);
    assert!(
        keys.iter().any(|k| k == "\\windows\\system32\\driver.sys"),
        "the current name still places the file: {keys:?}"
    );
    assert!(!keys.iter().any(|k| k.contains("winsxs\\amd64_driver\\driver.sys")));
    assert_eq!(report.stats.unresolved, 0, "the file was seen, so it is not a lost file");
    assert_eq!(report.stats.unresolved_links, 1, "one name could not be placed, and is counted");
    assert_eq!(report.stats.stale_parent_links, 1);
}

#[test]
fn a_hard_link_whose_names_are_both_current_is_walked_twice() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    let store = builder.directories(ROOT_RECORD, "Windows\\WinSxS\\amd64_driver");

    let driver = builder.resident_file(system32, "driver.sys", b"MZ a driver", Presence::Live);
    builder.add_link(driver, store, 1, "driver.sys");
    let volume = builder.open();

    let (keys, report) = walk(&volume);
    assert!(keys.iter().any(|k| k == "\\windows\\system32\\driver.sys"));
    assert!(keys.iter().any(|k| k == "\\windows\\winsxs\\amd64_driver\\driver.sys"));
    assert_eq!(report.stats.extra_links_seen, 1);
    assert_eq!(report.stats.unresolved, 0);
    assert_eq!(report.stats.unresolved_links, 0);
    assert_eq!(report.stats.stale_parent_links, 0);
}

#[test]
fn a_volume_with_no_reuse_is_unchanged_and_says_the_check_ran() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    for i in 0..ORPHANS {
        builder.resident_file(temp, &format!("t{i}.exe"), b"MZ", Presence::Live);
    }
    let (keys, report) = walk(&builder.open());

    assert_eq!(report.stats.unresolved, 0);
    assert_eq!(report.stats.unresolved_links, 0);
    assert_eq!(report.stats.stale_parent_links, 0);
    assert!(report.stats.sequence_check_applied, "the check ran and found nothing");
    assert!(report.lost_reasons.is_empty(), "{:?}", report.lost_reasons);
    assert!(report.lost.is_empty());
    assert!(report.stats.parent_links_seen >= keys.len() as u64);
}

#[test]
fn a_volume_whose_sequences_make_no_sense_is_resolved_without_them() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    for i in 0..ORPHANS {
        builder.resident_file(temp, &format!("t{i}.exe"), b"MZ", Presence::Live);
    }
    builder.set_every_parent_sequence(900);
    let (keys, report) = walk(&builder.open());

    assert!(!report.stats.sequence_check_applied, "the walk must not believe this");
    assert!(report.stats.stale_parent_links > 0, "and it must still say what it saw");
    assert_eq!(report.stats.unresolved, 0, "nothing was dropped on the strength of it");
    assert_eq!(
        keys.iter().filter(|k| k.starts_with("\\users\\bob\\appdata\\local\\temp\\")).count(),
        ORPHANS,
        "every file still walks: {keys:?}"
    );
}

#[test]
fn the_reason_tally_covers_every_lost_place_and_not_just_the_listed_ones() {
    const PLACES: usize = 40;
    const PER_PLACE: usize = 3;

    let mut builder = Builder::with_records(512);
    windows(&mut builder);

    let app =
        builder.directories(ROOT_RECORD, r"Program Files\Google\Chrome\Application\150.0.7871.187");
    let mut version = builder.directory(app, "v0");
    for place in 0..PLACES {
        if place > 0 && place % 7 == 0 {
            version = builder.directory(app, &format!("v{}", place / 7));
        }
        let locales = builder.directory(version, &format!("L{place}"));
        let pak =
            builder.resident_file(locales, &format!("sw_{place}.pak"), b"pak data", Presence::Live);
        builder.set_sequence(pak, NOW);
        let orphaned = builder.directory(pak, "Locales");
        builder.set_parent_sequence(orphaned, THEN);
        for i in 0..PER_PLACE {
            builder.resident_file(orphaned, &format!("{place}_{i}.pak"), b"old", Presence::Deleted);
        }
    }

    let (_keys, report) = walk(&builder.open());
    let stats = report.stats;

    assert_eq!(stats.unresolved_directories, PLACES as u64, "forty places were lost");
    assert_eq!(
        report.lost.len(),
        32,
        "the list is still capped, which is what makes the tally worth having"
    );

    let tallied_places: u64 = report.lost_reasons.iter().map(|(_, places, _)| places).sum();
    let tallied_names: u64 = report.lost_reasons.iter().map(|(_, _, names)| names).sum();
    assert_eq!(tallied_places, PLACES as u64, "{:?}", report.lost_reasons);
    assert_eq!(tallied_names, stats.unresolved_links, "{:?}", report.lost_reasons);
    assert_eq!(tallied_names, (PLACES * PER_PLACE) as u64);

    assert_eq!(report.lost_reasons.len(), 1, "one shape here: {:?}", report.lost_reasons);
    assert_eq!(report.lost_reasons[0].0, LostReason::StaleParentReference);

    assert_eq!(stats.unresolved_files_deleted, (PLACES * PER_PLACE) as u64);
    assert_eq!(stats.unresolved_live(), 0);
    assert_eq!(stats.files_lost(), 0, "forty places of pure wreckage enlarge nothing");
}

#[test]
fn deleted_wreckage_and_a_lost_live_directory_are_counted_apart() {
    let mut builder = Builder::new();
    windows(&mut builder);

    let locales = builder.directories(
        ROOT_RECORD,
        "Program Files\\Google\\Chrome\\Application\\150.0.7871.187\\Locales",
    );
    let pak = builder.resident_file(locales, "sw_NEUTER.pak", b"pak data", Presence::Live);
    builder.set_sequence(pak, NOW);
    let orphaned = builder.directory(pak, "Locales");
    builder.set_parent_sequence(orphaned, THEN);
    for i in 0..ORPHANS {
        builder.resident_file(orphaned, &format!("{i}_NEUTER.pak"), b"old", Presence::Deleted);
    }

    let vendor = builder.directories(ROOT_RECORD, "Program Files (x86)\\Samsung");
    let magician = builder.directory(vendor, "Samsung Magician");
    let decoy = builder.resident_file(vendor, "decoy.exe", b"MZ", Presence::Live);
    builder.spill_index(magician, IndexLayout::AllocationInExtension);
    builder.spill_file_name(magician);
    builder.misdirect_file_name(magician, decoy);
    const LIVE_LOST: usize = 4;
    for i in 0..LIVE_LOST {
        builder.resident_file(magician, &format!("tool{i}.exe"), b"MZ", Presence::Live);
    }

    let (keys, report) = walk(&builder.open());
    let stats = report.stats;

    assert!(!keys.iter().any(|k| k.contains("samsung magician")), "{keys:?}");
    assert!(!keys.iter().any(|k| k.ends_with("_neuter.pak") && k.contains("locales\\locales")));

    assert_eq!(stats.unresolved, (ORPHANS + LIVE_LOST) as u64);
    assert_eq!(stats.unresolved_directories, 2, "two places, and they are not the same kind");

    assert_eq!(stats.unresolved_files_deleted, ORPHANS as u64, "the wreckage");
    assert_eq!(stats.unresolved_live(), LIVE_LOST as u64, "the hole");

    assert_eq!(stats.unparsable, 1, "the lost directory's own record is the damage");
    assert_eq!(
        stats.files_lost(),
        LIVE_LOST as u64 + 1,
        "a free record the walk placed at no name is not a place a live sample can be"
    );
    assert_eq!(stats.enumeration().files_lost, LIVE_LOST as u64 + 1);
    assert_eq!(
        stats.unresolved + stats.unparsable + stats.records_unreadable,
        (ORPHANS + LIVE_LOST) as u64 + 1,
        "the old sum, kept here so the difference is a measurement and not a claim"
    );

    let reasons: Vec<LostReason> = report.lost.iter().map(|l| l.reason).collect();
    assert!(reasons.contains(&LostReason::StaleParentReference), "{reasons:?}");
    assert!(reasons.contains(&LostReason::NameNotRecovered), "{reasons:?}");

    let tallied_places: u64 = report.lost_reasons.iter().map(|(_, places, _)| places).sum();
    let tallied_names: u64 = report.lost_reasons.iter().map(|(_, _, names)| names).sum();
    assert_eq!(
        tallied_places, stats.unresolved_directories,
        "the tally is over every place, not the truncated list: {:?}",
        report.lost_reasons
    );
    assert_eq!(
        tallied_names, stats.unresolved_links,
        "every unplaceable name is attributed to exactly one reason: {:?}",
        report.lost_reasons
    );
    assert!(
        report.lost_reasons.windows(2).all(|w| w[0].2 >= w[1].2),
        "worst first: {:?}",
        report.lost_reasons
    );
    let stale = report
        .lost_reasons
        .iter()
        .find(|(reason, _, _)| *reason == LostReason::StaleParentReference)
        .expect("the stale place is in the tally");
    assert_eq!((stale.1, stale.2), (1, ORPHANS as u64));
    let unnamed = report
        .lost_reasons
        .iter()
        .find(|(reason, _, _)| *reason == LostReason::NameNotRecovered)
        .expect("the live lost place is in the tally");
    assert_eq!((unnamed.1, unnamed.2), (1, LIVE_LOST as u64));

    assert!(
        stats.deleted_seen >= ORPHANS as u64,
        "every free record the walk read is counted, placed or not: {}",
        stats.deleted_seen
    );
}

#[test]
fn a_deleted_file_the_walk_can_place_is_still_seen_and_still_deleted() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    builder.resident_file(temp, "dropper.exe", b"MZ gone", Presence::Deleted);

    let (keys, report) = walk(&builder.open());
    assert!(
        keys.iter().any(|k| k == "\\users\\bob\\appdata\\local\\temp\\dropper.exe"),
        "the deleted record still yields its path, which is what recovers it: {keys:?}"
    );
    assert_eq!(report.stats.deleted_seen, 1);
    assert_eq!(report.stats.unresolved, 0);
    assert_eq!(report.stats.unresolved_files_deleted, 0);
    assert_eq!(report.stats.files_lost(), 0, "nothing was lost: the walk placed it");
}

#[test]
fn deleted_seen_counts_records_and_not_names() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let other = builder.directories(ROOT_RECORD, "Users\\bob\\Downloads");
    let dropper = builder.resident_file(temp, "dropper.exe", b"MZ", Presence::Deleted);
    builder.add_link(dropper, other, 0, "copy.exe");

    let (keys, report) = walk(&builder.open());
    assert_eq!(
        keys.iter().filter(|k| k.starts_with("\\users\\bob\\")).count(),
        2,
        "both names walk: {keys:?}"
    );
    assert_eq!(report.stats.extra_links_seen, 1);
    assert_eq!(report.stats.deleted_seen, 1, "one record, two names");
}

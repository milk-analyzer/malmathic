#![cfg(test)]

use std::io::Cursor;

use mm_raw::Volume;

use crate::hostile_index::metered;
use crate::testimage::{Builder, IndexLayout, Presence, INDEX_RECORD, RECORD, ROOT_RECORD};

const DIRECTORY: &str = r"\Windows\System32\drivers";

const CHILDREN: [&str; 12] = [
    "aaa.sys", "bbb.sys", "ccc.sys", "ddd.sys", "eee.sys", "fff.sys", "ggg.sys", "hhh.sys",
    "iii.sys", "jjj.sys", "kkk.sys", "lll.sys",
];

const IN_THE_SECOND_BUFFER: &str = "bbb.sys";

fn volume(layout: IndexLayout, damage: impl Fn(&mut Builder, u64)) -> Volume<Cursor<Vec<u8>>> {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let config = builder.directory(system32, "config");
    builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);
    let drivers = builder.directory(system32, "drivers");
    builder.spill_index(drivers, layout);
    for child in CHILDREN {
        builder.resident_file(drivers, child, b"MZ", Presence::Live);
    }
    damage(&mut builder, drivers);
    Volume::open(Cursor::new(builder.bytes()), "synthetic").expect("the synthetic volume opens")
}

fn intact(_: &mut Builder, _: u64) {}

fn sparse(builder: &mut Builder, directory: u64) {
    builder.sparse_index_buffer(directory, 1);
}

fn damaged(builder: &mut Builder, directory: u64) {
    builder.damage_index_buffer(directory, 1);
}

fn listed(volume: &Volume<Cursor<Vec<u8>>>) -> Vec<String> {
    let mut names: Vec<String> =
        volume.list_directory_entries(DIRECTORY).into_iter().map(|e| e.name).collect();
    names.sort();
    names
}

const LAYOUTS: [(&str, IndexLayout); 2] = [
    ("all three index attributes in the directory's own record", IndexLayout::LargeInBase),
    (
        "the $INDEX_ALLOCATION fragmented across extension records",
        IndexLayout::AllocationFragmentedByVcn,
    ),
];

#[test]
fn the_library_lists_a_sparse_index_buffer_short_and_reports_success() {
    let volume = volume(IndexLayout::LargeInBase, |b, d| b.sparse_index_buffer(d, 1));
    let record = volume
        .resolve(DIRECTORY)
        .expect("the directory itself still resolves: its parent is intact");
    let bytes = volume.fs().read_record(record).expect("the record reads");
    let listed = volume
        .fs()
        .directory_entries(&bytes)
        .expect("the library reports success on a directory it read half of")
        .into_iter()
        .filter(|e| e.file_name.is_some())
        .count();
    assert_eq!(listed, 6, "half the children are gone and nothing said so");
}

#[test]
fn the_guard_is_the_only_thing_standing_between_this_and_a_short_listing() {
    for (label, layout) in LAYOUTS {
        for (what, damage) in
            [("a sparse run", &sparse as &dyn Fn(&mut Builder, u64)), ("a BAAD buffer", &damaged)]
        {
            let broken = volume(layout, damage);
            let whole = volume(layout, &intact as &dyn Fn(&mut Builder, u64));

            assert_eq!(listed(&whole).len(), CHILDREN.len(), "{label}: the twin is healthy");
            assert!(
                whole.list_directory_entries_checked(DIRECTORY).is_ok(),
                "{label}: and nothing refuses it"
            );
            let error = broken
                .list_directory_entries_checked(DIRECTORY)
                .expect_err("the damaged fixture must be refused")
                .to_string();
            assert!(
                error.contains("lists short"),
                "{label}/{what}: refused for the reason this module is about, got: {error}"
            );
        }
    }
}

#[test]
fn a_sparse_index_buffer_is_refused_rather_than_listed_short() {
    for (label, layout) in LAYOUTS {
        let volume = volume(layout, |b, d| b.sparse_index_buffer(d, 1));
        let error = volume
            .list_directory_entries_checked(DIRECTORY)
            .expect_err("a directory missing an in-use index buffer must not list")
            .to_string();
        assert!(
            error.contains("$I30 $BITMAP") && error.contains("index record 1"),
            "{label}: the refusal must name the discriminator and the buffer, got: {error}"
        );
        assert!(listed(&volume).is_empty(), "{label}: and no short list leaks past it");
        assert_eq!(
            volume.resolve(&format!(r"{DIRECTORY}\{IN_THE_SECOND_BUFFER}")),
            None,
            "{label}: a file in the lost buffer stays unresolvable, which is honest"
        );
        assert_eq!(
            volume.resolve(&format!(r"{DIRECTORY}\{}", CHILDREN[0])),
            None,
            "{label}: and a file in the buffer that *did* read is refused too — the \
             directory is UNKNOWN, not partly known"
        );
    }
}

#[test]
fn a_damaged_index_buffer_is_refused_rather_than_listed_short() {
    for (label, layout) in LAYOUTS {
        let volume = volume(layout, |b, d| b.damage_index_buffer(d, 1));
        let error = volume
            .list_directory_entries_checked(DIRECTORY)
            .expect_err("a damaged in-use index buffer must not list")
            .to_string();
        assert!(
            error.contains("$I30 $BITMAP"),
            "{label}: the refusal must name the discriminator, got: {error}"
        );
        assert!(listed(&volume).is_empty(), "{label}: and no short list leaks past it");
    }
}

#[test]
fn a_gap_with_no_bitmap_is_refused() {
    for (label, layout) in LAYOUTS {
        let volume = volume(layout, |b, d| {
            b.sparse_index_buffer(d, 1);
            b.drop_index_bitmap(d);
        });
        let error = volume
            .list_directory_entries_checked(DIRECTORY)
            .expect_err("a gap that nothing on the volume explains must not list")
            .to_string();
        assert!(
            error.contains("no readable $I30 $BITMAP"),
            "{label}: the refusal must say the discriminator is missing, got: {error}"
        );
    }
}

#[test]
fn an_undamaged_large_directory_lists_whole_on_every_layout() {
    for layout in [
        IndexLayout::LargeInBase,
        IndexLayout::AllocationFragmentedByVcn,
        IndexLayout::AllocationInExtension,
        IndexLayout::WholeIndexInExtension,
        IndexLayout::SplitAcrossExtensions,
    ] {
        let volume = volume(layout, intact);
        let mut expected: Vec<String> = CHILDREN.iter().map(|c| c.to_string()).collect();
        expected.sort();
        assert_eq!(listed(&volume), expected, "{layout:?} must list every child");
        assert!(
            volume.resolve(&format!(r"{DIRECTORY}\{IN_THE_SECOND_BUFFER}")).is_some(),
            "{layout:?} must resolve a child past the first buffer"
        );
        assert!(volume.is_windows_install(), "{layout:?} must still be a Windows volume");
    }
}

#[test]
fn a_free_index_record_is_not_a_short_listing() {
    for (label, layout) in LAYOUTS {
        let volume = volume(layout, |b, d| {
            b.unused_index_buffer(d, 1);
            b.sparse_index_buffer(d, 1);
        });
        let mut expected: Vec<String> = CHILDREN.iter().map(|c| c.to_string()).collect();
        expected.sort();
        assert_eq!(
            listed(&volume),
            expected,
            "{label}: a free index record must cost the directory nothing"
        );
        assert!(
            volume.list_directory_entries_checked(DIRECTORY).is_ok(),
            "{label}: and must not be refused"
        );
    }
}

#[test]
fn a_small_directory_needs_no_bitmap() {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let drivers = builder.directory(system32, "drivers");
    let small = &CHILDREN[..4];
    for child in small {
        builder.resident_file(drivers, child, b"MZ", Presence::Live);
    }
    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic").expect("the volume opens");

    let mut expected: Vec<String> = small.iter().map(|c| c.to_string()).collect();
    expected.sort();
    assert_eq!(listed(&volume), expected);
    assert!(volume.list_directory_entries_checked(DIRECTORY).is_ok());
}

fn machine(layout: IndexLayout, damage: impl Fn(&mut Builder, u64)) -> Builder {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let drivers = builder.directory(system32, "drivers");
    builder.spill_index(drivers, layout);
    for child in CHILDREN {
        builder.resident_file(drivers, child, b"MZ", Presence::Live);
    }
    damage(&mut builder, drivers);
    builder
}

fn cost_of_listing(builder: Builder) -> (usize, u64, usize) {
    let (volume, meter) = metered(builder);
    let before = meter.snapshot();
    let listed = volume.list_directory_entries(DIRECTORY).len();
    let after = meter.snapshot().since(&before);
    (after.reads, after.bytes, listed)
}

#[test]
fn a_healthy_large_directory_costs_no_more_than_its_buffers() {
    let (reads, bytes, listed) = cost_of_listing(machine(IndexLayout::LargeInBase, intact));
    assert_eq!(listed, CHILDREN.len(), "the control has to be a complete listing");

    assert_eq!(reads, 6, "a healthy large directory took {reads} reads");
    assert_eq!(bytes, 4 * RECORD as u64 + 2 * INDEX_RECORD as u64, "it read {bytes} bytes");

    let free = cost_of_listing(machine(IndexLayout::LargeInBase, |b, d| {
        b.unused_index_buffer(d, 1);
        b.damage_index_buffer(d, 1);
    }));
    assert_eq!(
        (free.0, free.1),
        (reads, bytes),
        "consulting the bitmap cost {} reads and {} bytes",
        free.0 as i64 - reads as i64,
        free.1 as i64 - bytes as i64
    );
    assert_eq!(free.2, CHILDREN.len(), "and it still listed the whole directory");
}

#[test]
fn a_root_that_says_it_has_index_buffers_and_has_none_is_refused() {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let drivers = builder.directory(system32, "drivers");
    builder.spill_index(drivers, IndexLayout::AllocationInExtension);
    for child in CHILDREN {
        builder.resident_file(drivers, child, b"MZ", Presence::Live);
    }
    let elsewhere = builder.directories(ROOT_RECORD, r"Users\bob\Downloads");
    builder.resident_file(elsewhere, "invoice.pdf.exe", b"MZ", Presence::Live);
    builder.misdirect_index(drivers, elsewhere);

    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic").expect("it opens");

    let error = volume
        .list_directory_entries_checked(DIRECTORY)
        .expect_err("a directory whose index buffers are unreachable must not list")
        .to_string();
    assert!(
        error.contains("no $INDEX_ALLOCATION could be found"),
        "the refusal must say what is missing, got: {error}"
    );
    assert!(listed(&volume).is_empty(), "and no listing leaks past it");
    assert_eq!(
        volume.list_directory(r"\Users\bob\Downloads"),
        ["invoice.pdf.exe"],
        "while the directory the list pointed at is untouched: the refusal is about \
         this directory, not about the volume"
    );
}

#[test]
fn a_bitmap_bit_past_the_end_of_the_value_is_refused() {
    for (label, layout) in LAYOUTS {
        let volume = volume(layout, |b, d| b.claim_index_buffer_in_use(d, 5));
        let error = volume
            .list_directory_entries_checked(DIRECTORY)
            .expect_err("a directory with index records it never read must not list")
            .to_string();
        assert!(
            error.contains("index record 5") && error.contains("only 2 were read"),
            "{label}: the refusal must say how far short the read fell, got: {error}"
        );
        assert!(listed(&volume).is_empty(), "{label}: and no short list leaks past it");
    }
}

#[test]
fn clearing_the_large_index_flag_is_refused() {
    let volume = volume(IndexLayout::LargeInBase, |b, d| b.clear_large_index_flag(d));
    let error = volume
        .list_directory_entries_checked(DIRECTORY)
        .expect_err("a directory whose root disowns its own index buffers must not list")
        .to_string();
    assert!(
        error.contains("says it has no index buffers") && error.contains("at least one is in use"),
        "the refusal must name both halves of the contradiction, got: {error}"
    );
    assert!(listed(&volume).is_empty(), "and no empty listing leaks past it");
}

#[test]
fn a_directory_that_shrank_back_to_one_node_still_lists() {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
    let drivers = builder.directory(system32, "drivers");
    builder.spill_index(drivers, IndexLayout::LargeInBase);
    for child in &CHILDREN[..4] {
        builder.resident_file(drivers, child, b"MZ", Presence::Live);
    }
    builder.clear_large_index_flag(drivers);
    builder.unused_index_buffer(drivers, 0);
    builder.unused_index_buffer(drivers, 1);
    let volume = Volume::open(Cursor::new(builder.bytes()), "synthetic").expect("it opens");

    assert!(
        volume.list_directory_entries_checked(DIRECTORY).is_ok(),
        "an emptied $INDEX_ALLOCATION is an ordinary thing for a volume to carry"
    );
}

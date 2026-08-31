#![cfg(test)]

use std::io::Cursor;

use mm_raw::Volume;

use crate::testimage::{
    Builder, IndexLayout, Presence, CLUSTER, INDEX_RECORD, ROOT_RECORD, SECTOR,
};

const HIVES: [&str; 5] = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

fn windows_image(layout: IndexLayout, non_resident_list: bool) -> (Vec<u8>, u64) {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);

    let config = builder.directory(system32, "config");
    builder.spill_index(config, layout);
    if non_resident_list {
        builder.spill_attribute_list(config);
    }
    for hive in HIVES {
        builder.resident_file(config, hive, b"regf", Presence::Live);
    }

    (builder.bytes(), config)
}

fn windows_volume(layout: IndexLayout) -> (Volume<Cursor<Vec<u8>>>, u64) {
    let (image, config) = windows_image(layout, false);
    (Volume::open(Cursor::new(image), "synthetic").expect("the synthetic volume opens"), config)
}

fn entries_from_base_record(
    volume: &Volume<Cursor<Vec<u8>>>,
    record: u64,
) -> Result<usize, String> {
    let bytes = volume.fs().read_record(record).expect("the record reads");
    volume.fs().directory_entries(&bytes).map(|e| e.len()).map_err(|e| e.to_string())
}

#[test]
fn an_extension_record_points_back_at_its_base() {
    let (volume, config) = windows_volume(IndexLayout::RootInExtension);
    const BASE_RECORD: usize = 0x20;
    let base_reference_of = |record: u64| -> u64 {
        let bytes = volume.fs().read_record(record).expect("the record reads");
        u64::from_le_bytes(bytes[BASE_RECORD..BASE_RECORD + 8].try_into().unwrap())
    };

    assert_eq!(base_reference_of(config), 0, "a base record's base_record is zero");

    let extension = base_reference_of(config + 1);
    assert_eq!(
        extension >> 48,
        1,
        "the reference back must carry the base's sequence number, not just its number"
    );
    assert_eq!(extension & 0x0000_FFFF_FFFF_FFFF, config);
}

#[test]
fn the_base_record_of_a_spilled_directory_is_not_a_directory_on_its_own() {
    let (volume, config) = windows_volume(IndexLayout::RootInExtension);

    let error = entries_from_base_record(&volume, config)
        .expect_err("the base record carries no $INDEX_ROOT, so listing it must fail");
    assert!(
        error.contains("$INDEX_ROOT"),
        "expected the VM's `record has no $INDEX_ROOT`, got: {error}"
    );

    let identity = volume.record_identity(config).expect("the record has a $FILE_NAME");
    assert_eq!(identity.name, "config");
    assert!(identity.in_use);

    assert!(volume.exists("\\Windows\\System32\\config\\SYSTEM"));
}

#[test]
fn resolve_walks_through_a_spilled_directory() {
    let (volume, config) = windows_volume(IndexLayout::RootInExtension);

    let hive = volume
        .resolve("\\Windows\\System32\\config\\SYSTEM")
        .expect("SYSTEM resolves through the spilled directory");
    assert_ne!(hive, config);
    assert_eq!(volume.read("\\Windows\\System32\\config\\SYSTEM").unwrap(), b"regf");

    assert!(volume.exists("\\windows\\system32\\CONFIG\\system"));
}

#[test]
fn list_directory_returns_a_spilled_directorys_children() {
    let (volume, _) = windows_volume(IndexLayout::RootInExtension);

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"]);
}

#[test]
fn a_volume_whose_config_is_spilled_is_still_a_windows_install() {
    let (volume, _) = windows_volume(IndexLayout::RootInExtension);
    assert!(volume.is_windows_install(), "the volume was rejected: {}", volume.why_not_windows());
}

#[test]
fn a_whole_index_in_one_extension_record_lists_completely() {
    let (volume, config) = windows_volume(IndexLayout::WholeIndexInExtension);

    assert!(entries_from_base_record(&volume, config).is_err(), "the base must still fail alone");
    assert!(volume.is_windows_install(), "{}", volume.why_not_windows());

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(
        names,
        ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"],
        "the children live in the $INDEX_ALLOCATION, so a record without it lists none of them"
    );
}

#[test]
fn an_index_split_across_two_extension_records_still_lists_completely() {
    let (volume, _) = windows_volume(IndexLayout::SplitAcrossExtensions);

    assert!(volume.exists("\\Windows\\System32\\config"));
    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(
        names,
        ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"],
        "the allocation is in another record, and its children must still be found"
    );

    assert!(volume.exists("\\Windows\\System32\\config\\SYSTEM"));
    assert!(volume.is_windows_install());
}

#[test]
fn the_diagnosis_agrees_with_the_verdict() {
    for layout in [
        IndexLayout::RootInExtension,
        IndexLayout::WholeIndexInExtension,
        IndexLayout::SplitAcrossExtensions,
        IndexLayout::AllocationInExtension,
        IndexLayout::AllocationFragmentedByVcn,
        IndexLayout::Resident,
    ] {
        let (volume, _) = windows_volume(layout);
        assert!(volume.is_windows_install(), "{layout:?} should be readable now");

        let why = volume.why_not_windows();
        assert!(
            why.contains("both markers resolve"),
            "{layout:?}: the verdict says Windows, the diagnosis says: {why}"
        );
    }
}

#[test]
fn an_allocation_alone_in_an_extension_record_is_still_found() {
    let (volume, config) = windows_volume(IndexLayout::AllocationInExtension);

    assert_eq!(
        entries_from_base_record(&volume, config),
        Ok(0),
        "the base lists, and lists nothing"
    );

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"]);
    assert!(volume.is_windows_install());
}

#[test]
fn the_same_directory_unspilled_lists_everything() {
    let (volume, config) = windows_volume(IndexLayout::Resident);

    assert_eq!(entries_from_base_record(&volume, config), Ok(5));
    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, ["DEFAULT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM"]);
    assert!(volume.is_windows_install());
}

#[test]
fn an_attribute_list_pointing_into_nowhere_is_refused_rather_than_followed() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Windows\\System32\\config");
    builder.resident_file(dir, "SYSTEM", b"regf", Presence::Live);
    builder.spill_index(dir, IndexLayout::RootInExtension);
    builder.misdirect_index(dir, u64::MAX - 1);
    let volume = builder.open();

    assert!(!volume.exists("\\Windows\\System32\\config\\SYSTEM"));
    assert_eq!(volume.list_directory("\\Windows\\System32\\config"), Vec::<String>::new());
    assert!(!volume.is_windows_install());
    assert!(!volume.why_not_windows().is_empty());
}

fn allocation_fragments(image: &[u8], directory: u64) -> Vec<(u64, Vec<u8>, ntfs_core::Attribute)> {
    const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
    const ATTR_INDEX_ALLOCATION: u32 = 0xA0;

    let fs = ntfs_core::NtfsFs::open(Cursor::new(image.to_vec())).expect("the image opens");
    let base = fs.read_record(directory).expect("the base record reads");
    let attrs = attributes_of(&base);
    let list = attrs
        .iter()
        .find(|a| a.type_code == ATTR_ATTRIBUTE_LIST)
        .expect("a spilled directory has an $ATTRIBUTE_LIST");
    let content =
        list.resident_content(&base).expect("this fixture keeps the list resident").to_vec();
    let entries = ntfs_core::parse_attribute_list(&content).expect("the list parses");

    entries
        .iter()
        .filter(|e| e.type_code == ATTR_INDEX_ALLOCATION)
        .map(|entry| {
            let number = entry.base_reference.record_number;
            let record = fs.read_record(number).expect("the named record reads");
            let attribute = attributes_of(&record)
                .into_iter()
                .find(|a| {
                    a.type_code == ATTR_INDEX_ALLOCATION && start_vcn_of(a) == Some(entry.start_vcn)
                })
                .expect("the record holds the fragment the list names");
            (number, record, attribute)
        })
        .collect()
}

fn attributes_of(record: &[u8]) -> Vec<ntfs_core::Attribute> {
    let header = ntfs_core::MftRecordHeader::parse(record).expect("a FILE record");
    ntfs_core::parse_attributes(record, header.first_attribute_offset as usize)
        .expect("its attributes parse")
}

fn start_vcn_of(attribute: &ntfs_core::Attribute) -> Option<u64> {
    match attribute.body {
        ntfs_core::AttributeBody::NonResident { start_vcn, .. } => Some(start_vcn),
        ntfs_core::AttributeBody::Resident { .. } => None,
    }
}

fn real_size_of(attribute: &ntfs_core::Attribute) -> u64 {
    match attribute.body {
        ntfs_core::AttributeBody::NonResident { real_size, .. } => real_size,
        ntfs_core::AttributeBody::Resident { .. } => panic!("an allocation is never resident"),
    }
}

fn names_in_fragment(image: &[u8], record: &[u8], attribute: &ntfs_core::Attribute) -> Vec<String> {
    let mut reader = Cursor::new(image.to_vec());
    let value = ntfs_core::read_attribute_value(&mut reader, record, attribute, CLUSTER as u64)
        .expect("the fragment's value reads");

    let mut names = Vec::new();
    let mut at = 0;
    while at + INDEX_RECORD <= value.len() {
        if &value[at..at + 4] == b"INDX" {
            let mut buffer = value[at..at + INDEX_RECORD].to_vec();
            let entries = ntfs_core::parse_index_buffer(&mut buffer, INDEX_RECORD, SECTOR)
                .expect("the INDX buffer parses");
            names.extend(entries.into_iter().filter_map(|e| e.file_name.map(|f| f.name)));
        }
        at += INDEX_RECORD;
    }
    names.sort();
    names
}

fn all_hives() -> Vec<String> {
    let mut all: Vec<String> = HIVES.iter().map(|h| (*h).to_string()).collect();
    all.sort();
    all
}

#[test]
fn the_allocation_is_split_into_two_fragments_at_successive_vcns() {
    let (image, config) = windows_image(IndexLayout::AllocationFragmentedByVcn, false);
    let fragments = allocation_fragments(&image, config);

    assert_eq!(fragments.len(), 2, "the fixture is meant to be in two pieces");
    assert_eq!(start_vcn_of(&fragments[0].2), Some(0));
    assert_eq!(start_vcn_of(&fragments[1].2), Some(1));
    assert_ne!(
        fragments[0].0, fragments[1].0,
        "both fragments landed in one record, so nothing here is split"
    );

    assert_eq!(
        real_size_of(&fragments[0].2),
        2 * INDEX_RECORD as u64,
        "the VCN 0 fragment carries the size of the whole attribute"
    );
    assert_eq!(
        real_size_of(&fragments[1].2),
        0,
        "a fragment past VCN 0 declares no size, which is what NTFS writes"
    );
}

#[test]
fn neither_fragment_of_a_split_allocation_is_the_whole_directory() {
    let (image, config) = windows_image(IndexLayout::AllocationFragmentedByVcn, false);
    let fragments = allocation_fragments(&image, config);

    let first = names_in_fragment(&image, &fragments[0].1, &fragments[0].2);
    let second = names_in_fragment(&image, &fragments[1].1, &fragments[1].2);

    assert!(
        !first.is_empty() && first.len() < HIVES.len(),
        "the VCN 0 fragment should hold some but not all of {} children, it held {first:?}",
        HIVES.len()
    );
    assert!(
        second.is_empty(),
        "a fragment declaring no size reads as empty; this one yielded {second:?}"
    );

    let runs = ntfs_core::data::attribute_runlist(&fragments[1].1, &fragments[1].2)
        .expect("the fragment's runlist decodes");
    let lcn = runs
        .first()
        .and_then(|run| run.lcn)
        .expect("the fragment names a cluster rather than a hole");

    let mut both: Vec<String> = first.into_iter().chain(names_in_cluster(&image, lcn)).collect();
    both.sort();
    assert_eq!(both, all_hives(), "the fixture lost a child somewhere that is not the split");
}

fn names_in_cluster(image: &[u8], lcn: u64) -> Vec<String> {
    let start = lcn as usize * CLUSTER;
    let mut buffer = image[start..start + INDEX_RECORD].to_vec();
    assert_eq!(&buffer[..4], b"INDX", "cluster {lcn} does not hold an index buffer");
    ntfs_core::parse_index_buffer(&mut buffer, INDEX_RECORD, SECTOR)
        .expect("the INDX buffer parses")
        .into_iter()
        .filter_map(|e| e.file_name.map(|f| f.name))
        .collect()
}

#[test]
fn a_fragmented_allocation_lists_every_child() {
    let (volume, config) = windows_volume(IndexLayout::AllocationFragmentedByVcn);

    assert_eq!(entries_from_base_record(&volume, config), Ok(0));

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, all_hives(), "the children past the first fragment were lost");

    for hive in HIVES {
        assert!(
            volume.exists(&format!("\\Windows\\System32\\config\\{hive}")),
            "{hive} does not resolve through the reassembled index"
        );
    }
    assert!(volume.is_windows_install(), "{}", volume.why_not_windows());
}

#[test]
fn a_non_resident_attribute_list_has_no_resident_content() {
    const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
    let list_of = |image: Vec<u8>, record: u64| {
        let fs = ntfs_core::NtfsFs::open(Cursor::new(image)).expect("the image opens");
        let base = fs.read_record(record).expect("the base record reads");
        let list = attributes_of(&base)
            .into_iter()
            .find(|a| a.type_code == ATTR_ATTRIBUTE_LIST)
            .expect("a spilled directory has an $ATTRIBUTE_LIST");
        (base, list)
    };

    let (image, config) = windows_image(IndexLayout::RootInExtension, true);
    let (base, list) = list_of(image, config);
    assert!(list.non_resident, "the fixture was meant to move the list out into clusters");
    assert!(
        list.resident_content(&base).is_none(),
        "a non-resident attribute has no bytes in its record; this is where the walk used to end"
    );

    let (image, config) = windows_image(IndexLayout::RootInExtension, false);
    let (base, list) = list_of(image, config);
    assert!(!list.non_resident);
    assert!(list.resident_content(&base).is_some());
}

#[test]
fn a_directory_whose_attribute_list_is_non_resident_still_lists() {
    let (image, _) = windows_image(IndexLayout::RootInExtension, true);
    let volume = Volume::open(Cursor::new(image), "synthetic").expect("the volume opens");

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, all_hives());

    assert_eq!(volume.read("\\Windows\\System32\\config\\SYSTEM").unwrap(), b"regf");
    assert!(volume.is_windows_install(), "{}", volume.why_not_windows());
}

#[test]
fn a_non_resident_list_naming_a_fragmented_allocation_still_lists() {
    let (image, _) = windows_image(IndexLayout::AllocationFragmentedByVcn, true);
    let volume = Volume::open(Cursor::new(image), "synthetic").expect("the volume opens");

    let mut names = volume.list_directory("\\Windows\\System32\\config");
    names.sort();
    assert_eq!(names, all_hives());
    assert!(volume.is_windows_install(), "{}", volume.why_not_windows());
}

#[test]
fn a_non_resident_list_pointing_into_nowhere_is_refused_rather_than_followed() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Windows\\System32\\config");
    builder.resident_file(dir, "SYSTEM", b"regf", Presence::Live);
    builder.spill_index(dir, IndexLayout::RootInExtension);
    builder.spill_attribute_list(dir);
    builder.misdirect_index(dir, u64::MAX - 1);
    let volume = builder.open();

    assert!(!volume.exists("\\Windows\\System32\\config\\SYSTEM"));
    assert_eq!(volume.list_directory("\\Windows\\System32\\config"), Vec::<String>::new());
    assert!(!volume.is_windows_install());
    assert!(!volume.why_not_windows().is_empty());
}

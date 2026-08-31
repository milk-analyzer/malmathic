#![cfg(test)]

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use mm_raw::Volume;

use crate::testimage::{Builder, IndexLayout, Presence, RECORD, ROOT_RECORD};

fn compromised_machine() -> (Builder, Machine) {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);

    let config = builder.directory(system32, "config");
    builder.spill_index(config, IndexLayout::RootInExtension);
    for hive in ["SYSTEM", "SOFTWARE", "SAM"] {
        builder.resident_file(config, hive, b"regf", Presence::Live);
    }

    let decoy = builder.directories(ROOT_RECORD, "Users\\bob\\Downloads");
    let planted = builder.resident_file(decoy, "invoice.pdf.exe", b"MZ", Presence::Live);

    (builder, Machine { config, decoy, planted })
}

struct Machine {
    config: u64,
    decoy: u64,
    planted: u64,
}

const CONFIG: &str = "\\Windows\\System32\\config";
const SYSTEM_HIVE: &str = "\\Windows\\System32\\config\\SYSTEM";

fn hives() -> Vec<String> {
    ["SAM", "SOFTWARE", "SYSTEM"].iter().map(|s| s.to_string()).collect()
}

fn listing<R: Read + Seek>(volume: &Volume<R>, path: &str) -> Vec<String> {
    let mut names = volume.list_directory(path);
    names.sort();
    names
}

fn refuses_quietly<R: Read + Seek>(volume: &Volume<R>) {
    assert!(volume.exists(CONFIG));
    assert_eq!(listing(volume, CONFIG), Vec::<String>::new());
    assert!(!volume.exists(SYSTEM_HIVE));
    assert!(!volume.is_windows_install());
    assert!(!volume.why_not_windows().is_empty());
}

#[test]
fn a_foreign_directorys_index_is_not_served_as_this_directorys() {
    let (mut builder, machine) = compromised_machine();
    builder.misdirect_index(machine.config, machine.decoy);
    let volume = builder.open();

    let decoy_bytes = volume.fs().read_record(machine.decoy).expect("the decoy record reads");
    let decoy_entries = volume.fs().directory_entries(&decoy_bytes).expect("and it lists");
    assert!(
        decoy_entries
            .iter()
            .any(|e| { e.file_name.as_ref().map(|f| f.name.as_str()) == Some("invoice.pdf.exe") }),
        "the decoy has to be a working directory, or this test proves nothing"
    );

    let (honest, _) = compromised_machine();
    assert_eq!(listing(&honest.open(), CONFIG), hives());

    refuses_quietly(&volume);
    assert!(
        !volume.list_directory(CONFIG).iter().any(|n| n == "invoice.pdf.exe"),
        "the decoy's children were served as config's"
    );
    assert!(!volume.exists("\\Windows\\System32\\config\\invoice.pdf.exe"));
    assert_eq!(listing(&volume, "\\Users\\bob\\Downloads"), ["invoice.pdf.exe"]);
}

#[test]
fn a_file_record_named_as_an_index_holder_is_refused() {
    let (mut builder, machine) = compromised_machine();
    builder.misdirect_index(machine.config, machine.planted);
    let volume = builder.open();

    refuses_quietly(&volume);
}

#[test]
fn an_entry_pointing_at_its_own_record_terminates() {
    let (mut builder, machine) = compromised_machine();
    builder.misdirect_index(machine.config, machine.config);
    let volume = builder.open();

    refuses_quietly(&volume);
}

#[test]
fn record_numbers_that_are_not_records_are_refused() {
    for target in [0u64, 4096, 1 << 40, u64::MAX - 1, u64::MAX] {
        let (mut builder, machine) = compromised_machine();
        builder.misdirect_index(machine.config, target);
        let volume = builder.open();

        assert_eq!(
            listing(&volume, CONFIG),
            Vec::<String>::new(),
            "record {target} yielded a listing"
        );
        assert!(!volume.is_windows_install(), "record {target} was accepted");
        assert!(!volume.why_not_windows().is_empty());
    }
}

#[test]
fn an_extension_record_with_its_own_attribute_list_is_read_and_not_followed() {
    let (mut builder, machine) = compromised_machine();
    let other = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.spill_index(other, IndexLayout::AllocationInExtension);
    builder.resident_file(other, "bait.tmp", b"x", Presence::Live);
    builder.misdirect_index(machine.config, other);

    let (volume, meter) = metered(builder);
    let before = meter.snapshot();
    assert_eq!(listing(&volume, CONFIG), Vec::<String>::new());
    let reads = meter.snapshot().reads - before.reads;

    assert_eq!(reads, 5, "the walk read {reads} records, so it followed something");
    assert!(!volume.exists("\\Windows\\System32\\config\\bait.tmp"));
}

#[test]
fn a_list_whose_content_runs_past_its_record_is_refused() {
    let (builder, machine) = compromised_machine();
    let mut image = builder.bytes();
    let attribute = attribute_list_offset(&image, machine.config);
    patch32(&mut image, attribute + 0x10, 0xFFFF_FFF0);

    refuses_quietly(&open(image));
}

#[test]
fn a_first_attribute_offset_outside_the_record_is_refused() {
    for offset in [0xFFFFu32, (RECORD - 2) as u32] {
        let (builder, machine) = compromised_machine();
        let mut image = builder.bytes();
        let record = record_offset(&image, machine.config);
        patch16(&mut image, record + 0x14, offset as u16);

        refuses_quietly(&open(image));
    }
}

#[test]
fn malformed_entry_lengths_in_the_list_are_refused() {
    for length in [0u16, 4, 0x1A, 0xFFFF] {
        let (builder, machine) = compromised_machine();
        let mut image = builder.bytes();
        let first_entry = attribute_list_offset(&image, machine.config) + 0x18;
        patch16(&mut image, first_entry + 0x04, length);

        let volume = open(image);
        assert_eq!(
            listing(&volume, CONFIG),
            Vec::<String>::new(),
            "entry length {length} yielded a listing"
        );
        assert!(!volume.why_not_windows().is_empty());
    }
}

const MAX_PADDING: usize = (740 - 104) / 40;

const MAX_CANDIDATES: usize = 8;

#[test]
fn a_list_padded_to_the_end_of_the_record_is_followed_only_as_far_as_the_cap() {
    let (mut builder, machine) = compromised_machine();
    let targets: Vec<u64> = (0..MAX_PADDING as u64).map(|i| 100 + i).collect();
    builder.pad_attribute_list(machine.config, &targets);

    let (volume, meter) = metered(builder);
    let before = meter.snapshot();
    let started = std::time::Instant::now();
    let names = listing(&volume, CONFIG);
    let elapsed = started.elapsed();
    let reads = meter.snapshot().reads - before.reads;

    assert_eq!(MAX_PADDING, 15, "the arithmetic above no longer describes the record");
    const { assert!(MAX_PADDING > MAX_CANDIDATES, "the cap has to be what stops the walk") };
    assert_eq!(names, hives(), "the padding cost the directory its listing");
    assert_eq!(reads, 3 + 1 + MAX_CANDIDATES, "the walk read {reads} records");
    assert!(elapsed < std::time::Duration::from_secs(1), "took {elapsed:?}");
}

#[test]
fn a_record_named_many_times_is_read_once() {
    let (mut builder, machine) = compromised_machine();
    let targets = vec![machine.decoy; MAX_PADDING];
    builder.pad_attribute_list(machine.config, &targets);
    builder.misdirect_index(machine.config, machine.decoy);

    let (volume, meter) = metered(builder);
    let before = meter.snapshot();
    assert_eq!(listing(&volume, CONFIG), Vec::<String>::new());
    let reads = meter.snapshot().reads - before.reads;

    assert_eq!(reads, 3 + 1 + 1, "{MAX_PADDING} entries naming one record cost {reads} reads");
}

fn list_in_a_cluster() -> (Builder, Machine) {
    let (mut builder, machine) = compromised_machine();
    builder.spill_attribute_list(machine.config);
    (builder, machine)
}

#[test]
fn a_non_resident_list_claiming_the_whole_volume_is_read_only_as_far_as_the_cap() {
    const MAX_ATTRIBUTE_LIST_BYTES: u64 = 64 * 1024;

    let (builder, machine) = list_in_a_cluster();
    let mut image = builder.bytes();
    let attribute = attribute_list_offset(&image, machine.config);
    let runs = attribute + 0x40;
    assert_eq!(image[runs], 0x44, "the list's runlist is not where this test patches");
    patch32(&mut image, runs + 1, 512);
    patch32(&mut image, attribute + 0x30, u32::MAX);

    let (volume, meter) = metered_image(image);
    let before = meter.snapshot();
    let started = std::time::Instant::now();
    let names = listing(&volume, CONFIG);
    let elapsed = started.elapsed();
    let cost = meter.snapshot().since(&before);

    assert_eq!(names, Vec::<String>::new());
    assert!(
        cost.bytes <= MAX_ATTRIBUTE_LIST_BYTES + 8 * RECORD as u64,
        "reading the list cost {} bytes against a {MAX_ATTRIBUTE_LIST_BYTES}-byte cap",
        cost.bytes
    );
    assert!(elapsed < std::time::Duration::from_secs(1), "took {elapsed:?}");
}

#[test]
fn a_non_resident_list_pointing_past_the_volume_is_refused() {
    let (builder, machine) = list_in_a_cluster();
    let mut image = builder.bytes();
    let runs = attribute_list_offset(&image, machine.config) + 0x40;
    patch32(&mut image, runs + 5, 0x7FFF_FFF0);

    refuses_quietly(&open(image));
}

#[test]
fn a_fragment_starting_past_the_end_of_the_attribute_is_refused() {
    let (mut builder, _) = compromised_machine();
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.spill_index(temp, IndexLayout::AllocationFragmentedByVcn);
    for name in ["a.tmp", "b.tmp", "c.tmp", "d.tmp"] {
        builder.resident_file(temp, name, b"x", Presence::Live);
    }
    let mut image = builder.bytes();

    let mut honest = listing(&open(image.clone()), "\\Windows\\Temp");
    honest.sort();
    assert_eq!(honest, ["a.tmp", "b.tmp", "c.tmp", "d.tmp"]);

    let attribute = record_offset(&image, temp + 2) + 0x38;
    patch32(&mut image, attribute + 0x10, 1 << 30);

    let volume = open(image);
    assert_eq!(
        listing(&volume, "\\Windows\\Temp"),
        Vec::<String>::new(),
        "a fragment starting a billion clusters along was accepted"
    );
    assert!(!volume.why_not_windows().is_empty());
}

#[test]
fn a_fragment_repeating_a_covered_vcn_does_not_displace_the_rest() {
    let (mut builder, _) = compromised_machine();
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.spill_index(temp, IndexLayout::AllocationFragmentedByVcn);
    for name in ["a.tmp", "b.tmp", "c.tmp", "d.tmp"] {
        builder.resident_file(temp, name, b"x", Presence::Live);
    }
    let mut image = builder.bytes();
    let attribute = record_offset(&image, temp + 2) + 0x38;
    patch32(&mut image, attribute + 0x10, 0);

    let volume = open(image);
    let names = listing(&volume, "\\Windows\\Temp");
    let mut unique = names.clone();
    unique.dedup();
    assert_eq!(names, unique, "a repeated fragment listed a child twice");
    assert!(names.len() < 4, "the overlap was read as though it were the rest of the index");
}

#[test]
fn an_ordinary_directory_costs_what_it_cost_before_the_fix() {
    let mut builder = Builder::new();
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ", Presence::Live);
    let config = builder.directory(system32, "config");
    builder.resident_file(config, "SYSTEM", b"regf", Presence::Live);

    let (volume, meter) = metered(builder);

    let before = meter.snapshot();
    let record = volume.resolve(SYSTEM_HIVE).expect("the hive resolves");
    let with_fix = meter.snapshot().since(&before);

    let before = meter.snapshot();
    let same = resolve_the_pre_fix_way(&volume, SYSTEM_HIVE).expect("and resolved before too");
    let without_fix = meter.snapshot().since(&before);

    assert_eq!(record, same);
    assert_eq!(
        with_fix,
        without_fix,
        "index_record changed what an ordinary resolution reads: {with_fix:?} against {without_fix:?}"
    );
    assert_eq!(with_fix.reads, 4);
    assert_eq!(with_fix.bytes, 4 * RECORD as u64);
}

#[test]
fn a_spilled_directory_costs_one_extra_read() {
    let (builder, _) = compromised_machine();
    let (volume, meter) = metered(builder);

    let before = meter.snapshot();
    assert!(volume.exists(SYSTEM_HIVE));
    let cost = meter.snapshot().since(&before);

    assert_eq!(cost.reads, 5);
    assert_eq!(cost.bytes, 5 * RECORD as u64);
}

fn resolve_the_pre_fix_way<R: Read + Seek>(volume: &Volume<R>, path: &str) -> Option<u64> {
    let mut current = ROOT_RECORD;
    for component in path.split('\\').filter(|c| !c.is_empty()) {
        let record = volume.fs().read_record(current).ok()?;
        let entries = volume.fs().directory_entries(&record).ok()?;
        let folded = component.to_lowercase();
        current = entries.iter().find_map(|e| {
            let name = e.file_name.as_ref()?;
            (name.name.to_lowercase() == folded).then_some(e.file_reference.record_number)
        })?;
    }
    Some(current)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reads {
    pub(crate) reads: usize,
    pub(crate) bytes: u64,
}

impl Reads {
    pub(crate) fn since(self, before: &Reads) -> Reads {
        Reads { reads: self.reads - before.reads, bytes: self.bytes - before.bytes }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Meter {
    reads: Arc<AtomicUsize>,
    bytes: Arc<AtomicU64>,
}

impl Meter {
    pub(crate) fn snapshot(&self) -> Reads {
        Reads {
            reads: self.reads.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct Counted {
    inner: Cursor<Vec<u8>>,
    meter: Meter,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.meter.reads.fetch_add(1, Ordering::Relaxed);
        self.meter.bytes.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

impl Seek for Counted {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

pub(crate) fn metered(builder: Builder) -> (Volume<Counted>, Meter) {
    let meter = Meter::default();
    let counted = Counted { inner: Cursor::new(builder.bytes()), meter: meter.clone() };
    (Volume::open(counted, "metered").expect("the synthetic volume opens"), meter)
}

pub(crate) fn open(image: Vec<u8>) -> Volume<Cursor<Vec<u8>>> {
    Volume::open(Cursor::new(image), "patched").expect("the synthetic volume opens")
}

pub(crate) fn metered_image(image: Vec<u8>) -> (Volume<Counted>, Meter) {
    let meter = Meter::default();
    let counted = Counted { inner: Cursor::new(image), meter: meter.clone() };
    (Volume::open(counted, "metered").expect("the synthetic volume opens"), meter)
}

pub(crate) fn record_offset(image: &[u8], record: u64) -> usize {
    let sector = u16::from_le_bytes([image[0x0B], image[0x0C]]) as usize;
    let cluster = sector * image[0x0D] as usize;
    let mft_lcn = u64::from_le_bytes(image[0x30..0x38].try_into().expect("eight bytes")) as usize;
    mft_lcn * cluster + record as usize * RECORD
}

pub(crate) fn attribute_list_offset(image: &[u8], record: u64) -> usize {
    const ATTRIBUTE_LIST: u32 = 0x20;
    const END: u32 = 0xFFFF_FFFF;

    let start = record_offset(image, record);
    let mut at = start + 0x38;
    loop {
        let type_code = u32::from_le_bytes(image[at..at + 4].try_into().expect("four bytes"));
        assert_ne!(type_code, END, "record {record} has no $ATTRIBUTE_LIST");
        if type_code == ATTRIBUTE_LIST {
            return at;
        }
        let length =
            u32::from_le_bytes(image[at + 4..at + 8].try_into().expect("four bytes")) as usize;
        assert!(length >= 16, "record {record} has an attribute of length {length}");
        at += length;
        assert!(at < start + RECORD, "record {record} has no $ATTRIBUTE_LIST");
    }
}

fn patch16(image: &mut [u8], at: usize, value: u16) {
    assert!(at % 512 < 500, "patching {at} would land in the update-sequence tail");
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn patch32(image: &mut [u8], at: usize, value: u32) {
    assert!(at % 512 < 500, "patching {at} would land in the update-sequence tail");
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

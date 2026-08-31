#![cfg(test)]

use crate::hostile_index::{attribute_list_offset, metered_image, open, patch32, record_offset};
use crate::testimage::{Builder, Presence};

const ATTR_DATA: u32 = 0x80;

fn victim_and_neighbour() -> (Builder, u64, Vec<u8>, Vec<u8>) {
    let victim_bytes = b"VICTIM ORIGINAL CONTENT".to_vec();
    let neighbour_bytes = b"ATTACKER CHOSEN CONTENT, ENTIRELY DIFFERENT".to_vec();

    let mut builder = Builder::new();
    let victim = builder.file(5, "victim.bin", &victim_bytes, Presence::Live);
    let neighbour = builder.file(5, "neighbour.bin", &neighbour_bytes, Presence::Live);
    builder.spill_unnamed_data(victim);
    builder.misdirect_spilled_attributes(victim, neighbour);
    (builder, victim, victim_bytes, neighbour_bytes)
}

#[test]
fn a_misdirected_attribute_list_cannot_lend_this_file_another_files_bytes() {
    let (builder, victim, victim_bytes, neighbour_bytes) = victim_and_neighbour();
    let volume = builder.open();

    let borrowed = volume
        .fs()
        .read_data_by_record(victim, None, u64::MAX)
        .expect("ntfs-core answers this read, which is the whole problem");
    assert_eq!(borrowed, neighbour_bytes, "the unchecked follower stopped reproducing the defect");
    let neighbour = volume.resolve(r"\neighbour.bin").expect("the neighbour resolves");
    assert_eq!(
        volume.fs().runs_by_record(victim, None).unwrap(),
        volume.fs().runs_by_record(neighbour, None).unwrap(),
        "the unchecked follower stopped adopting the neighbour's runlist"
    );

    let err = volume.read(r"\victim.bin").unwrap_err().to_string();
    assert!(mm_raw::describes_an_unaccounted_attribute_list(&err), "{err}");
    assert!(volume.read_record_capped(victim, usize::MAX).is_err());
    assert!(volume.wof_backing(victim).is_none());
    assert!(volume.data_runs(victim).is_empty(), "the carver was handed the neighbour's clusters");

    assert_eq!(volume.read(r"\neighbour.bin").unwrap(), neighbour_bytes);
    assert_ne!(victim_bytes, neighbour_bytes);
}

#[test]
fn a_named_stream_read_cannot_borrow_a_neighbours_stream() {
    let mut builder = Builder::new();
    let victim = builder.file(5, "victim.bin", b"MZ victim", Presence::Live);
    let neighbour = builder.file(5, "neighbour.bin", b"MZ neighbour", Presence::Live);
    builder.alternate_stream(neighbour, "Zone.Identifier", b"[ZoneTransfer]ZoneId=3");
    builder.spill_unnamed_data(victim);
    builder.misdirect_spilled_attributes(victim, neighbour);
    let volume = builder.open();

    assert_eq!(
        volume.fs().read_data_by_record(victim, Some("Zone.Identifier"), u64::MAX).unwrap(),
        b"[ZoneTransfer]ZoneId=3",
        "the fixture stopped reproducing the borrowed stream"
    );
    let err =
        volume.read_named_stream(r"\victim.bin", "Zone.Identifier", 4096).unwrap_err().to_string();
    assert!(mm_raw::describes_an_unaccounted_attribute_list(&err), "{err}");
}

fn claim_as_extension_of(image: &mut [u8], record: u64, base: u64) {
    let at = record_offset(image, record) + 0x20;
    assert!(at % 512 < 500, "patching {at} would land in the update-sequence tail");
    image[at..at + 8].copy_from_slice(&((1u64 << 48) | base).to_le_bytes());
}

#[test]
fn a_list_longer_than_the_ceiling_costs_a_refusal_rather_than_a_read_per_entry() {
    const CEILING: usize = 16;

    let mut cost_at: Vec<(usize, usize, bool)> = Vec::new();
    for pad in [0usize, CEILING, CEILING + 1, 64, 120] {
        let mut builder = Builder::with_records(2000);
        let mut targets: Vec<u64> = Vec::new();
        for i in 0..pad {
            targets.push(builder.resident_file(
                5,
                &format!("filler{i}.txt"),
                b"NOT THE VICTIM",
                Presence::Deleted,
            ));
        }
        let victim = builder.file(5, "victim.bin", b"VICTIM", Presence::Live);
        builder.spill_named_stream(victim, "Zone.Identifier");
        builder.pad_attribute_list_of(victim, ATTR_DATA, &targets);
        builder.spill_attribute_list(victim);

        let mut image = builder.bytes();
        for target in &targets {
            claim_as_extension_of(&mut image, *target, victim);
        }
        let (volume, meter) = metered_image(image);
        let before = meter.snapshot();
        let read = volume.read_record_capped(victim, usize::MAX);
        let reads = meter.snapshot().since(&before).reads;
        cost_at.push((pad, reads, read.is_ok()));
    }

    assert!(cost_at[0].2, "an unpadded list stopped reading: {cost_at:?}");
    assert!(cost_at[1].2, "a list at the ceiling was refused: {cost_at:?}");
    for (pad, _, ok) in &cost_at[2..] {
        assert!(!ok, "a list of {pad} entries was followed rather than refused: {cost_at:?}");
    }
    let at_seventeen = cost_at[2].1;
    for (pad, reads, _) in &cost_at[3..] {
        assert!(
            *reads <= at_seventeen + 4,
            "a list of {pad} entries cost {reads} reads against {at_seventeen} for {}: {cost_at:?}",
            CEILING + 1
        );
    }
}

#[test]
fn a_list_longer_than_the_cap_on_reading_one_is_refused_rather_than_read_as_a_prefix() {
    const CAP: usize = 64 * 1024;
    const ENTRY: usize = 32;

    let mut builder = Builder::with_records(2000);
    let victim = builder.file(5, "victim.bin", b"VICTIM", Presence::Live);
    let neighbour = builder.file(5, "neighbour.bin", b"NOT THE VICTIM", Presence::Live);
    builder.spill_named_stream(victim, "Zone.Identifier");

    let benign = CAP / ENTRY + 64;
    let mut targets: Vec<u64> = vec![victim; benign];
    targets.extend([neighbour; 8]);
    builder.pad_attribute_list_of(victim, ATTR_DATA, &targets);
    builder.spill_attribute_list_across(victim, 24);
    let volume = builder.open();

    assert!((benign + 8) * ENTRY > CAP, "the tail is not past the cap");

    let err = volume.read_record_capped(victim, usize::MAX).unwrap_err().to_string();
    assert!(mm_raw::describes_an_unaccounted_attribute_list(&err), "{err}");
    assert!(!volume.spilled_records(victim).is_complete());
}

#[test]
fn a_list_declaring_more_bytes_than_it_has_is_refused() {
    let mut builder = Builder::with_records(2000);
    let victim = builder.file(5, "victim.bin", b"VICTIM", Presence::Live);
    builder.spill_named_stream(victim, "Zone.Identifier");
    builder.spill_attribute_list(victim);
    let mut image = builder.bytes();

    assert_eq!(open(image.clone()).read_record_capped(victim, usize::MAX).unwrap(), b"VICTIM");

    let at = attribute_list_offset(&image, victim) + 0x30;
    patch32(&mut image, at, 128 * 1024);
    let volume = open(image);

    let err = volume.read_record_capped(victim, usize::MAX).unwrap_err().to_string();
    assert!(mm_raw::describes_an_unaccounted_attribute_list(&err), "{err}");
}

#[test]
fn a_soundly_spilled_file_still_reads_whole() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = crate::compact_os::raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    builder.file(5, "plain.bin", b"MZ ordinary", Presence::Live);
    let packed = builder.compact_os_file(
        5,
        "packed.bin",
        content.len() as u64,
        mm_raw::wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_reparse_point(packed);
    builder.spill_unnamed_data(packed);
    let volume = builder.open();

    assert_eq!(volume.read(r"\plain.bin").unwrap(), b"MZ ordinary");
    assert_eq!(volume.read(r"\packed.bin").unwrap(), content);
    assert!(volume.wof_backing(packed).is_some());
    assert!(!volume.data_runs(packed).is_empty());
    assert!(volume.spilled_records(packed).is_complete(), "a sound list was refused");
    assert_eq!(volume.spilled_records(packed).records().len(), 1);
}

#[test]
fn the_ownership_check_is_what_makes_the_difference() {
    let (builder, victim, _, neighbour_bytes) = victim_and_neighbour();
    let volume = builder.open();

    assert!(!volume.spilled_records(victim).is_complete(), "the follower stopped refusing");
    assert_eq!(volume.spilled_records(victim).refused(), 1);
    assert_eq!(
        volume.fs().read_data_by_record(victim, None, u64::MAX).unwrap(),
        neighbour_bytes,
        "the unvalidated read stopped producing the wrong file"
    );
}

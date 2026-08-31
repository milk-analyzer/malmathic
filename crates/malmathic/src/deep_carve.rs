#![cfg(test)]

use std::io::{Read, Seek};

use mm_core::{
    Acquisition, ArtifactSource, Candidate, CandidateId, FileHash, NormalizedPath, Observation,
    ObservationKind, Recovery,
};
use mm_raw::Volume;

use crate::acquire::{
    ClusterMap, OrphanIndex, QuarantineStore, RecycleBinStore, SampleDir, ShadowStore,
};
use crate::deep;
use crate::testimage::{Builder, Presence, ROOT_RECORD};

fn pe(len: usize, filler: u8) -> Vec<u8> {
    assert!(len >= 0x200, "a PE needs room for its own headers");
    let mut bytes = vec![0u8; len];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    let lfanew: u32 = 0x80;
    bytes[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
    let nt = lfanew as usize;
    bytes[nt..nt + 4].copy_from_slice(b"PE\0\0");
    bytes[nt + 4..nt + 6].copy_from_slice(&0x014cu16.to_le_bytes());
    bytes[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
    bytes[nt + 20..nt + 22].copy_from_slice(&224u16.to_le_bytes());
    let optional = nt + 24;
    bytes[optional..optional + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[optional + 92..optional + 96].copy_from_slice(&4u32.to_le_bytes());
    let section = optional + 224;
    bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
    let raw_size = (len - 0x200) as u32;
    bytes[section + 16..section + 20].copy_from_slice(&raw_size.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    for byte in bytes[0x200..].iter_mut() {
        *byte = filler;
    }
    bytes
}

fn pe_naming_itself(len: usize, filler: u8, pdb: &str) -> Vec<u8> {
    let mut bytes = pe(len, filler);
    let nt = 0x80usize;
    let optional = nt + 24;
    let section = optional + 224;
    let virtual_address = 0x1000u32;
    let raw_offset = 0x200usize;
    bytes[section + 12..section + 16].copy_from_slice(&virtual_address.to_le_bytes());

    let data_at = 0x400usize;
    let table_at = 0x500usize;
    assert!(table_at + 28 < len, "the image must have room for a debug directory");
    bytes[data_at..data_at + 4].copy_from_slice(b"RSDS");
    for byte in bytes[data_at + 4..data_at + 24].iter_mut() {
        *byte = 0;
    }
    bytes[data_at + 24..data_at + 24 + pdb.len()].copy_from_slice(pdb.as_bytes());
    bytes[data_at + 24 + pdb.len()] = 0;

    let mut entry = vec![0u8; 28];
    entry[12..16].copy_from_slice(&2u32.to_le_bytes());
    entry[24..28].copy_from_slice(&(data_at as u32).to_le_bytes());
    bytes[table_at..table_at + 28].copy_from_slice(&entry);

    bytes[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
    let debug = optional + 96 + 6 * 8;
    let rva = virtual_address + (table_at - raw_offset) as u32;
    bytes[debug..debug + 4].copy_from_slice(&rva.to_le_bytes());
    bytes[debug + 4..debug + 8].copy_from_slice(&28u32.to_le_bytes());
    bytes
}

#[test]
fn an_image_that_names_itself_is_carved_for_a_candidate_no_artifact_hashed() {
    let payload = pe_naming_itself(24_064, 0xC3, "D:\\build\\release\\server.pdb");
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(temp, "server.exe", &payload, Presence::Deleted);
    let volume = builder.open();

    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates = vec![candidate_without_recorded_hash("C:\\Windows\\Temp\\server.exe")];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);

    let targets = deep::targets(&candidates, &[0]);
    assert_eq!(targets.len(), 1, "no digest, but the path gives a name to look for");

    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert_eq!(scan.hits.len(), 1, "the image names itself server.pdb, so it answers");
    let hit = &scan.hits[0];
    assert_eq!(hit.bytes, payload, "and the bytes are the file's own");
    assert_eq!(
        hit.matched,
        deep::Matched::SelfName { carried: "server.pdb".to_string() },
        "matched by the name inside the image, not by a digest nobody recorded"
    );

    let acquisition = deep::adopt(&mut candidates[0], hit, &dir);
    let Acquisition::Bytes { via, recovery: Recovery::Unverified { basis }, .. } = &acquisition
    else {
        panic!("a name is not a digest, so this can never be Confirmed: {acquisition:?}")
    };
    assert_eq!(*via, ArtifactSource::UnallocatedClusters);
    assert!(basis.contains("names ITSELF `server.pdb`"), "{basis}");
    assert!(basis.contains("not the filesystem's"), "{basis}");
    assert!(basis.contains("a second copy of the same program"), "{basis}");
    assert!(
        candidates[0].hash.is_empty(),
        "a name-matched carve must not become the candidate's identity"
    );
}

#[test]
fn an_image_naming_another_program_is_not_offered_for_this_one() {
    let payload = pe_naming_itself(24_064, 0xC3, "D:\\build\\release\\updater.pdb");
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(temp, "server.exe", &payload, Presence::Deleted);
    let volume = builder.open();

    let mut clusters = ClusterMap::new();
    let candidates = vec![candidate_without_recorded_hash("C:\\Windows\\Temp\\server.exe")];
    let targets = deep::targets(&candidates, &[0]);
    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert!(scan.hits.is_empty(), "`updater` is not `server`, so nothing was taken");
    assert!(scan.headers > 0, "and it did read the image before deciding that");
}

fn windows(builder: &mut Builder) {
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
}

fn case_sample_dir() -> SampleDir {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "malmathic-deep-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a case directory");
    SampleDir { path: dir, relative: "sample", write_out: true }
}

fn candidate_with_recorded_hash(path_str: &str, bytes: &[u8]) -> Candidate {
    let mut c = Candidate::new(CandidateId(1), -7.8);
    c.path = NormalizedPath::parse(path_str);
    c.observe(Observation::about_path(
        ArtifactSource::ShimCache,
        NormalizedPath::parse(path_str).unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    ));
    let sha1 = FileHash::compute(bytes).sha1_hex().expect("sha1 of the sample");
    c.observe(
        Observation::about_path(
            ArtifactSource::Amcache,
            NormalizedPath::parse(path_str).unwrap(),
            ObservationKind::HashRecovered,
        )
        .with_hash(FileHash::from_sha1_hex(&sha1).expect("a sha1")),
    );
    c
}

fn candidate_without_recorded_hash(path_str: &str) -> Candidate {
    let mut c = Candidate::new(CandidateId(1), -7.8);
    c.path = NormalizedPath::parse(path_str);
    c.observe(Observation::about_path(
        ArtifactSource::ShimCache,
        NormalizedPath::parse(path_str).unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    ));
    c
}

fn ordinary_chain<R: Read + Seek>(
    volume: &Volume<R>,
    clusters: &mut ClusterMap,
    candidate: &mut Candidate,
    dir: &SampleDir,
) -> Acquisition {
    let quarantine = QuarantineStore::new();
    let recycle_bin = RecycleBinStore::new();
    let shadows = ShadowStore::none();
    let orphans = OrphanIndex::default();
    crate::acquire::acquire(
        volume,
        &quarantine,
        &recycle_bin,
        &shadows,
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        clusters,
        candidate,
        dir,
    )
}

fn record_reallocated_clusters_intact(payload: &[u8]) -> Builder {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(
        temp,
        "server.exe",
        payload,
        Presence::RecordReallocatedClustersFree("MpSigStub.log"),
    );
    builder
}

#[test]
fn the_ordinary_chain_fails_when_the_record_has_been_reallocated() {
    let payload = pe(24_064, 0xA7);
    let volume = record_reallocated_clusters_intact(&payload).open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidate = candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload);

    match ordinary_chain(&volume, &mut clusters, &mut candidate, &dir) {
        Acquisition::HashOnly { via } => assert_eq!(via, ArtifactSource::Amcache),
        other => panic!("the ordinary chain was supposed to fail, got {other:?}"),
    }
    assert!(
        !dir.path.join("C001.bin").exists(),
        "the ordinary chain must not have written any bytes"
    );
}

#[test]
fn a_reallocated_record_with_intact_clusters_is_recovered_from_free_space() {
    let payload = pe(24_064, 0xA7);
    let volume = record_reallocated_clusters_intact(&payload).open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);

    let targets = deep::targets(&candidates, &[0]);
    assert_eq!(targets.len(), 1, "a candidate with no bytes and a recorded digest is a target");

    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert_eq!(scan.hits.len(), 1, "the payload is in free space and nothing overwrote it");

    let acquisition = deep::adopt(&mut candidates[0], &scan.hits[0], &dir);
    match &acquisition {
        Acquisition::Bytes { via, size, recovery, saved_as } => {
            assert_eq!(
                *via,
                ArtifactSource::UnallocatedClusters,
                "never reported as an $MFT carve"
            );
            assert_eq!(*size, payload.len() as u64);
            assert!(
                matches!(recovery, Recovery::Confirmed { .. }),
                "a digest match is proof and nothing weaker may be printed: {recovery:?}"
            );
            assert!(recovery.is_trustworthy());
            let written = std::fs::read(dir.path.join(saved_as.rsplit('/').next().unwrap()))
                .expect("the sample was written");
            assert_eq!(written, payload, "the bytes in sample/ are the file, byte for byte");
        }
        other => panic!("expected bytes, got {other:?}"),
    }
    assert_eq!(
        candidates[0].acquired_hash.as_ref().map(FileHash::sha1_hex),
        Some(FileHash::compute(&payload).sha1_hex())
    );
}

#[test]
fn the_confirmation_says_it_came_from_free_space_and_names_the_cluster() {
    let payload = pe(24_064, 0xA7);
    let volume = record_reallocated_clusters_intact(&payload).open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);
    let targets = deep::targets(&candidates, &[0]);
    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    let acquisition = deep::adopt(&mut candidates[0], &scan.hits[0], &dir);

    let Acquisition::Bytes { recovery: Recovery::Confirmed { against }, .. } = &acquisition else {
        panic!("expected a confirmation, got {acquisition:?}");
    };
    assert!(against.contains("Amcache"), "names the artifact whose digest matched: {against}");
    assert!(
        against.contains("unallocated"),
        "says the bytes came out of free space rather than off a record: {against}"
    );
    assert!(
        against.contains("no filesystem record naming them"),
        "says what it does NOT have, which is the whole caveat: {against}"
    );
}

#[test]
fn overwritten_clusters_recover_nothing_and_the_reason_does_not_overclaim() {
    let payload = pe(24_064, 0xA7);
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(
        temp,
        "server.exe",
        &payload,
        Presence::RecordReallocatedClustersOverwritten("MpSigStub.log"),
    );
    let volume = builder.open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);

    let targets = deep::targets(&candidates, &[0]);
    assert_eq!(targets.len(), 1);
    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert!(scan.hits.is_empty(), "the bytes are not there and must not be invented");

    let reason = deep::no_hit_reason(&targets[0], &scan, "the file is gone");
    assert!(reason.contains("none of them answers to the"), "says what was compared: {reason}");
    assert!(reason.contains("Amcache recorded"), "and names who recorded it: {reason}");
    assert!(
        reason.contains("contiguous") && reason.contains("fragments"),
        "states the limit of carving rather than declaring the file absent: {reason}"
    );
    assert!(
        !reason.contains("the bytes are gone")
            || reason.contains("not evidence the bytes are gone"),
        "must never assert absence: {reason}"
    );
    assert!(
        !dir.path.join("C001.bin").exists(),
        "nothing may be written when nothing was identified"
    );
}

#[test]
fn a_decoy_executable_in_free_space_is_examined_and_not_saved() {
    let payload = pe(24_064, 0xA7);
    let decoy = pe(8_192, 0x5C);
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(temp, "leftover.exe", &decoy, Presence::RecordReallocatedClustersFree("a.log"));
    let volume = builder.open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);

    let targets = deep::targets(&candidates, &[0]);
    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert!(scan.headers >= 1, "the decoy's header was found: {scan:?}");
    assert!(scan.hashed >= 1, "and it was measured and hashed rather than assumed");
    assert!(scan.hits.is_empty(), "but it is not this file, so nothing was recovered");
    assert!(
        std::fs::read_dir(&dir.path).unwrap().next().is_none(),
        "and the sample directory is empty, which is better than holding the wrong file"
    );
}

#[test]
fn a_candidate_with_no_recorded_digest_is_searched_for_by_the_name_it_may_carry() {
    let payload = pe(24_064, 0xA7);
    let volume = record_reallocated_clusters_intact(&payload).open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates = vec![candidate_without_recorded_hash("C:\\Windows\\Temp\\server.exe")];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);
    assert!(
        matches!(candidates[0].acquisition, Acquisition::Failed { .. }),
        "the ordinary chain has nothing for it"
    );

    let targets = deep::targets(&candidates, &[0]);
    assert_eq!(targets.len(), 1, "no digest, but an image may still name itself");
    assert!(
        deep::no_hit_reason(&targets[0], &deep::Scan::default(), "gone")
            .contains("the name `server` an image may carry inside itself"),
        "the reason must say what was compared"
    );
    assert!(deep::unsearchable(&candidates, &[0]).is_empty(), "it IS searchable, by that name");

    let hypothetical =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    assert!(
        matches!(hypothetical[0].acquisition, Acquisition::NotAttempted),
        "the state every candidate on the reference laptop is in"
    );
    let armed = deep::targets(&hypothetical, &[0]);
    assert_eq!(armed.len(), 1, "a digest and no live file is the whole precondition");

    let mut nameless = candidate_without_recorded_hash("C:\\Windows\\Temp\\server.exe");
    nameless.path = None;
    let nameless = vec![nameless];
    assert!(deep::targets(&nameless, &[0]).is_empty(), "no digest and no name is nothing to find");
    assert_eq!(deep::unsearchable(&nameless, &[0]).len(), 1, "counted and named");
}

#[test]
fn a_candidate_acquisition_never_reached_is_still_a_target() {
    let payload = pe(24_064, 0xA7);

    let one_letter = vec![candidate_without_recorded_hash("C:\\Windows\\Temp\\a.exe")];
    assert!(
        deep::targets(&one_letter, &[0]).is_empty(),
        "a one-letter stem would answer to half the disk, so it is not searched for by name"
    );

    let no_digest = vec![candidate_without_recorded_hash("C:\\Windows\\Temp\\server.exe")];
    assert_eq!(deep::targets(&no_digest, &[0]).len(), 1, "searchable by the name it may carry");

    let never_attempted = vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\b.exe", &payload)];
    let targets = deep::targets(&never_attempted, &[0]);
    assert_eq!(targets.len(), 1, "no bytes, no live file, and a digest to check");
    assert!(deep::unsearchable(&never_attempted, &[0]).is_empty(), "it IS searchable");

    let mut live = candidate_with_recorded_hash("C:\\Windows\\Temp\\c.exe", &payload);
    live.observe(Observation::about_path(
        ArtifactSource::Mft,
        NormalizedPath::parse("C:\\Windows\\Temp\\c.exe").unwrap(),
        ObservationKind::FileExists {
            size: payload.len() as u64,
            created: None,
            modified: None,
            mft_modified: None,
            record: Some(64),
        },
    ));
    let live = vec![live];
    assert!(matches!(live[0].acquisition, Acquisition::NotAttempted));
    assert!(deep::targets(&live, &[0]).is_empty(), "the file is there; do not carve for it");
    assert!(deep::unsearchable(&live, &[0]).is_empty(), "nor is it an unsearchable miss");
}

#[test]
fn qualifying_candidates_past_the_cap_are_counted_rather_than_dropped_in_silence() {
    let payload = pe(24_064, 0xA7);
    let n = deep::MAX_TARGETS + 7;
    let candidates: Vec<_> = (0..n)
        .map(|i| candidate_with_recorded_hash(&format!("C:\\Windows\\Temp\\s{i}.exe"), &payload))
        .collect();
    let order: Vec<usize> = (0..n).collect();
    assert_eq!(deep::targets(&candidates, &order).len(), deep::MAX_TARGETS);
    assert_eq!(deep::over_the_cap(&candidates, &order), 7);

    assert_eq!(deep::over_the_cap(&candidates[..4], &[0, 1, 2, 3]), 0);
}

#[test]
fn a_candidate_that_already_has_its_file_is_not_searched_for() {
    let payload = pe(24_064, 0xA7);
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(temp, "server.exe", &payload, Presence::Live);
    let volume = builder.open();
    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);
    assert!(matches!(candidates[0].acquisition, Acquisition::Bytes { .. }));

    assert!(deep::targets(&candidates, &[0]).is_empty());
    assert!(deep::unsearchable(&candidates, &[0]).is_empty());
}

#[test]
fn a_run_with_no_targets_reads_nothing() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let volume = builder.open();
    let mut clusters = ClusterMap::new();
    assert!(
        deep::scan(&volume, &mut clusters, &[]).is_none(),
        "an empty target list is refused before any read"
    );
}

#[test]
fn crafted_pe_headers_are_refused_rather_than_followed() {
    let good = pe(4096, 0x11);
    assert_eq!(deep::pe_image_length_for_test(&good), Some(4096));

    assert_eq!(deep::pe_image_length_for_test(&good[..0x20]), None);

    for lfanew in [0u32, 0x10, 0x3c, u32::MAX, 0xFFFF_FFF0] {
        let mut bytes = good.clone();
        bytes[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        assert_eq!(deep::pe_image_length_for_test(&bytes), None, "e_lfanew {lfanew:#x}");
    }

    let mut bytes = good.clone();
    bytes[0x80 + 6..0x80 + 8].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(deep::pe_image_length_for_test(&bytes), None);

    let mut bytes = good.clone();
    bytes[0x80 + 6..0x80 + 8].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(deep::pe_image_length_for_test(&bytes), None);

    let mut bytes = good.clone();
    let section = 0x80 + 24 + 224;
    bytes[section + 16..section + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(deep::pe_image_length_for_test(&bytes), None);

    let mut bytes = good;
    bytes[0x80 + 20..0x80 + 22].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(deep::pe_image_length_for_test(&bytes), None);

    let mut bytes = vec![0u8; 4096];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    assert_eq!(deep::pe_image_length_for_test(&bytes), None);
}

#[test]
fn an_image_longer_than_its_free_run_is_not_carved() {
    let payload = pe(8_192, 0x33);
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Windows\\Temp");
    builder.file(temp, "server.exe", &payload, Presence::RecordReallocatedClustersFree("a.log"));
    builder.file(temp, "neighbour.dat", &vec![0x77u8; 8_192], Presence::Live);
    let volume = builder.open();

    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let mut candidates =
        vec![candidate_with_recorded_hash("C:\\Windows\\Temp\\server.exe", &payload)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);
    let targets = deep::targets(&candidates, &[0]);
    let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
    assert_eq!(scan.hits.len(), 1);
    assert_eq!(scan.hits[0].bytes.len(), payload.len());
    assert_eq!(scan.hits[0].bytes, payload);
}

fn triage_reallocated_record(deep: bool) -> (mm_report::Report, std::path::PathBuf, String) {
    use crate::testimage::Times;
    use mm_harvest::testhive::{utf16, Builder as Hive, REG_SZ_T, ROOT_FLAG};

    const SAMPLE_PATH: &str = r"c:\users\bob\appdata\roaming\fenix\fenix-agent.exe";
    let payload = pe(24_064, 0xA7);
    let sha1 = FileHash::compute(&payload).sha1_hex().expect("a sha-1");

    let mut hive = Hive::new();
    let root = hive.key("Root", ROOT_FLAG, true);
    let entry = hive.path(root, &["InventoryApplicationFile", "fenix-agent.exe|9a1c0f22e4"]);
    let path_value = hive.value("LowerCaseLongPath", REG_SZ_T, &utf16(SAMPLE_PATH), true);
    let id_value = hive.value("FileId", REG_SZ_T, &utf16(&format!("0000{sha1}")), true);
    let name_value = hive.value("Name", REG_SZ_T, &utf16("fenix-agent.exe"), true);
    let list = hive.value_list(&[path_value, id_value, name_value], true);
    hive.set_values(entry, list, 3);
    hive.set_last_written(entry, Times::at(1_760_000_000, 2_500_000));
    let amcache = hive.finish(root);

    let mut software = Hive::new();
    let root = software.key("ROOT", ROOT_FLAG, true);
    let run = software.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let evil = software.value(
        "FenixAgent",
        REG_SZ_T,
        &utf16(r"C:\Users\bob\AppData\Roaming\Fenix\fenix-agent.exe"),
        true,
    );
    let list = software.value_list(&[evil], true);
    software.set_values(run, list, 1);
    let software = software.finish(root);

    let mut image = Builder::new();
    let config = image.directories(ROOT_RECORD, r"Windows\System32\config");
    image.file(config, "SOFTWARE", &software, Presence::Live);
    let programs = image.directories(ROOT_RECORD, r"Windows\appcompat\Programs");
    image.file(programs, "Amcache.hve", &amcache, Presence::Live);

    let roaming = image.directories(ROOT_RECORD, r"Users\bob\AppData\Roaming\Fenix");
    image.file(
        roaming,
        "fenix-agent.exe",
        &payload,
        Presence::RecordReallocatedClustersFree("MpSigStub.log"),
    );

    let system32 = image.directories(ROOT_RECORD, r"Windows\System32");
    for name in ["notepad.exe", "kernel32.dll", "svchost.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }
    let volume = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-deep-e2e-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).expect("a case directory");

    let target = mm_report::Target {
        display_name: "synthetic".into(),
        device_path: "synthetic".into(),
        volume_serial: format!("{:016x}", volume.serial()),
    };
    let options = crate::pipeline::Options {
        output_dir: out.clone(),
        acquire_top: 10,
        write_samples: true,
        deep,
        verify_top: 10,
        progress: crate::progress::Style::Silent,
    };
    let report = crate::pipeline::run(&volume, mm_env::Environment::Recovery, target, &options);
    (report, out, sha1)
}

#[test]
fn without_the_flag_the_run_is_unchanged_and_reads_no_free_space() {
    let (report, _out, _sha1) = triage_reallocated_record(false);
    let found = report
        .candidates
        .iter()
        .find(|c| c.label().contains("fenix-agent.exe"))
        .expect("the sample is still a candidate");
    assert!(
        !matches!(found.acquisition, Acquisition::Bytes { .. }),
        "no bytes without --deep: {:?}",
        found.acquisition
    );
    let line = report
        .coverage
        .artifacts
        .iter()
        .find(|a| a.artifact.contains("unallocated clusters"))
        .expect("the stage reports itself even when it does nothing");
    let rendered = format!("{:?}", line.status);
    assert!(rendered.contains("--deep"), "names the flag that would run it: {rendered}");
}

#[test]
fn with_the_flag_the_sample_is_recovered_from_unallocated_space() {
    let (report, out, sha1) = triage_reallocated_record(true);
    let found = report
        .candidates
        .iter()
        .find(|c| c.label().contains("fenix-agent.exe"))
        .expect("the sample is a candidate");

    let Acquisition::Bytes { via, size, saved_as, recovery } = &found.acquisition else {
        panic!(
            "--deep should have recovered it; got {:?}\nwarnings: {:#?}",
            found.acquisition, report.coverage.warnings
        );
    };
    assert_eq!(*via, ArtifactSource::UnallocatedClusters);
    assert_eq!(*size, 24_064);
    assert!(matches!(recovery, Recovery::Confirmed { .. }), "{recovery:?}");
    assert!(recovery.is_trustworthy());

    let written = std::fs::read(out.join(saved_as.replace('/', "\\")))
        .expect("the sample is in the case directory");
    assert_eq!(FileHash::compute(&written).sha1_hex().as_deref(), Some(sha1.as_str()));

    assert!(
        report.coverage.warnings.iter().any(|w| w.contains("--deep searched")),
        "the cost is reported: {:#?}",
        report.coverage.warnings
    );
}

#[test]
#[ignore]
fn cost_of_a_sweep() {
    use std::time::Instant;

    const PASSES: usize = 60;
    let mut builder = Builder::with_geometry(64, 4_800);
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, r"Windows\Temp");
    let mut decoys = 0usize;
    for n in 0..16 {
        let name: &'static str = Box::leak(format!("leftover{n}.exe").into_boxed_str());
        builder.file(
            temp,
            name,
            &pe(65_536, n as u8),
            Presence::RecordReallocatedClustersFree(name),
        );
        decoys += 1;
    }
    let volume = builder.open();

    let mut clusters = ClusterMap::new();
    let dir = case_sample_dir();
    let absent = pe(24_064, 0xA7);
    let mut candidates = vec![candidate_with_recorded_hash(r"C:\Windows\Temp\server.exe", &absent)];
    candidates[0].acquisition = ordinary_chain(&volume, &mut clusters, &mut candidates[0], &dir);
    let targets = deep::targets(&candidates, &[0]);

    let started = Instant::now();
    let mut swept = 0u64;
    let mut headers = 0u64;
    let mut hashed = 0u64;
    for _ in 0..PASSES {
        let scan = deep::scan(&volume, &mut clusters, &targets).expect("the scan runs");
        assert!(scan.hits.is_empty(), "the target is not on this volume, by construction");
        swept += scan.bytes_read;
        headers = scan.headers;
        hashed = scan.hashed;
    }
    let elapsed = started.elapsed().as_secs_f64();

    println!(
        "sweep: {decoys} deleted executables planted in free space; per pass {headers} headers          followed, {hashed} images hashed; {PASSES} passes read {:.1} MB in {:.3} s => {:.0} MB/s          of free space, with the bytes already in memory",
        swept as f64 / (1024.0 * 1024.0),
        elapsed,
        (swept as f64 / (1024.0 * 1024.0)) / elapsed.max(1e-9),
    );
}

#[test]
#[ignore]
fn cost_of_hashing() {
    use std::time::Instant;
    let bytes = vec![0x5Au8; 64 * 1024 * 1024];
    let started = Instant::now();
    let _ = FileHash::compute(&bytes);
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "md5+sha1+sha256 over 64 MB in {:.3} s => {:.0} MB/s",
        elapsed,
        64.0 / elapsed.max(1e-9)
    );
}

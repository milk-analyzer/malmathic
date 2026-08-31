use mm_core::{
    ArtifactSource, Candidate, CandidateId, Evidence, NormalizedPath, Observation, ObservationKind,
    PersistenceKind,
};
use mm_score::baseline::BaselineBuilder;
use mm_score::weights::feature;
use mm_score::{Baseline, Weights};

const REALISTIC_PRIOR: f64 = -8.5;

fn path(p: &str) -> NormalizedPath {
    NormalizedPath::parse(p).unwrap()
}

fn fired(evidence: &[Evidence], name: &str) -> bool {
    evidence.iter().any(|e| e.feature == name)
}

fn usable_baseline() -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
    }
    b.build()
}

fn pe_with_code_section(name: &[u8; 8], body: &[u8]) -> Vec<u8> {
    const LFANEW: usize = 0x80;
    const OPTIONAL_SIZE: usize = 240;
    const MEM_EXECUTE: u32 = 0x2000_0000;

    let coff = LFANEW + 4;
    let optional = coff + 20;
    let table = optional + OPTIONAL_SIZE;
    let raw_offset = table + 48;

    let mut image = vec![0u8; raw_offset];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
    image[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
    image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
    image[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    image[table..table + 8].copy_from_slice(name);
    image[table + 8..table + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
    image[table + 16..table + 20].copy_from_slice(&(body.len() as u32).to_le_bytes());
    image[table + 20..table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
    image[table + 36..table + 40].copy_from_slice(&MEM_EXECUTE.to_le_bytes());
    image.extend_from_slice(body);
    image
}

fn crypted(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn compiled(len: usize) -> Vec<u8> {
    const OPCODES: &[u8] = &[0x48, 0x89, 0xe5, 0x00, 0x8b, 0x45, 0xc3, 0x00, 0x00, 0x55];
    (0..len).map(|i| OPCODES[i % OPCODES.len()]).collect()
}

fn score(file: &str, image: &[u8]) -> Vec<Evidence> {
    let p = path(file);
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.path = Some(p.clone());
    for observation in mm_harvest::pe::harvest(image, &p) {
        candidate.observe(observation);
    }
    mm_score::extract(&candidate, &usable_baseline(), &Weights::embedded())
}

#[test]
fn a_upx_packed_binary_scores_as_packed() {
    let image = pe_with_code_section(b"UPX1\0\0\0\0", &crypted(128 * 1024));
    let evidence = score("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe", &image);

    assert!(
        fired(&evidence, feature::HIGH_ENTROPY_CODE_SECTION),
        "the packing weight is unreachable again: {evidence:#?}"
    );
    assert!(
        !fired(&evidence, feature::PE_STRUCTURAL_ANOMALY),
        "packing is not a malformed header, and reporting it as one is a false sentence"
    );
    assert!(!fired(&evidence, feature::TIMESTOMPED), "packing is not an anti-forensic action");

    let packed = evidence.iter().find(|e| e.feature == feature::HIGH_ENTROPY_CODE_SECTION).unwrap();
    assert!(packed.log_lr > 0.0);
    assert!(packed.detail.contains("UPX1"), "{}", packed.detail);
    assert!(packed.detail.contains("bits/byte"), "{}", packed.detail);
}

#[test]
fn an_ordinary_compiled_binary_produces_nothing() {
    let image = pe_with_code_section(b".text\0\0\0", &compiled(128 * 1024));
    let found = mm_harvest::pe::harvest(&image, &path("C:\\Program Files\\App\\app.exe"));
    assert!(
        found.iter().all(|o| matches!(o.kind, ObservationKind::NoVersionResource)),
        "an ordinary compiled binary said something else: {found:#?}"
    );

    let evidence = score("C:\\Program Files\\App\\app.exe", &image);
    assert!(!fired(&evidence, feature::HIGH_ENTROPY_CODE_SECTION));
    assert!(!fired(&evidence, feature::PE_STRUCTURAL_ANOMALY));
    assert!(
        !fired(&evidence, feature::NO_VERSION_RESOURCE),
        "the version-resource row escaped the two zones it was measured in: {evidence:#?}"
    );
}

#[test]
fn a_missing_version_resource_is_priced_only_where_it_was_measured() {
    let image = pe_with_code_section(b".text\0\0\0", &compiled(128 * 1024));

    for quiet in [
        "C:\\Program Files\\App\\app.exe",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\app.exe",
        "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\app.exe",
        "C:\\ProgramData\\Vendor\\app.exe",
        "C:\\Users\\bob\\Downloads\\app.exe",
        "C:\\Windows\\Temp\\app.exe",
    ] {
        assert!(
            !fired(&score(quiet, &image), feature::NO_VERSION_RESOURCE),
            "priced in a zone where a third of the benign binaries have none: {quiet}"
        );
    }

    for loud in [
        "C:\\Windows\\System32\\svcupdate.exe",
        "C:\\Windows\\SysWOW64\\svcupdate.exe",
        "C:\\Windows\\WinSxS\\amd64_something_1.0\\svcupdate.exe",
    ] {
        let evidence = score(loud, &image);
        assert!(
            fired(&evidence, feature::NO_VERSION_RESOURCE),
            "not priced where it was measured to be rare: {loud}"
        );
        let row = evidence.iter().find(|e| e.feature == feature::NO_VERSION_RESOURCE).unwrap();
        assert!(row.log_lr > 0.0);
        assert!(row.detail.contains("version resource"), "{}", row.detail);
    }
}

#[test]
fn packing_alone_is_nowhere_near_a_finding() {
    let image = pe_with_code_section(b"UPX1\0\0\0\0", &crypted(128 * 1024));

    let probability = |file: &str| {
        let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
        candidate.evidence = score(file, &image);
        candidate.probability()
    };

    let installed = probability("C:\\Program Files\\VendorVPN\\vendorctrld.exe");
    assert!(installed < 0.02, "a packed vendor binary scored {installed:.3}");

    let staged = probability("C:\\Users\\bob\\AppData\\Local\\Temp\\vendor-tool.exe");
    assert!(staged < 0.2, "packed-and-in-temp scored {staged:.3} with no other evidence");
    assert!(staged > installed, "location should still count for something");
}

#[test]
fn the_two_crates_still_agree_on_the_technique_identifier() {
    let image = pe_with_code_section(b"UPX1\0\0\0\0", &crypted(128 * 1024));
    let observations: Vec<_> = mm_harvest::pe::harvest(&image, &path("C:\\Users\\bob\\x.exe"))
        .into_iter()
        .filter(|o| matches!(o.kind, ObservationKind::PeAnomaly { .. }))
        .collect();
    match &observations[0].kind {
        ObservationKind::PeAnomaly { detail } => {
            assert!(detail.contains("T1027.002"), "the routing key is gone: {detail}")
        }
        other => panic!("expected a PE anomaly, got {other:?}"),
    }
}

#[test]
fn the_measured_thresholds_are_what_ships() {
    assert_eq!(mm_harvest::pe::PACKED_ENTROPY, 7.2);
    assert_eq!(mm_harvest::pe::MIN_SECTION_BYTES, 16 * 1024);
}

#[test]
fn a_missing_version_resource_is_priced_once_the_machine_starts_the_file_itself() {
    let image = pe_with_code_section(b".text\0\0\0", &compiled(128 * 1024));

    for loud in [
        "C:\\Program Files\\Vendor\\svcupdate.exe",
        "C:\\ProgramData\\Vendor\\svcupdate.exe",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\svcupdate.exe",
        "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svcupdate.exe",
        "C:\\Users\\bob\\Downloads\\svcupdate.exe",
        "C:\\Windows\\Temp\\svcupdate.exe",
    ] {
        let evidence = score_with_persistence(loud, &image, PersistenceKind::Service);
        assert!(
            fired(&evidence, feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE),
            "an autostart target with no version resource earned nothing at {loud}: \\
             {evidence:#?}"
        );
        let row = evidence
            .iter()
            .find(|e| e.feature == feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE)
            .expect("just asserted");
        assert!(row.log_lr > 0.0);
        assert!(row.detail.contains("version resource"), "{}", row.detail);
        assert!(
            !fired(&evidence, feature::NO_VERSION_RESOURCE),
            "both version-resource rows fired on one file: {evidence:#?}"
        );
    }

    assert!(
        !fired(
            &score_with_persistence(
                "C:\\Tools\\internet_detector\\internet_detector.exe",
                &image,
                PersistenceKind::ScheduledTask
            ),
            feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE
        ),
        "priced in the one zone where a missing version resource is the ordinary case"
    );

    assert!(
        !fired(
            &score("C:\\Program Files\\Vendor\\svcupdate.exe", &image),
            feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE
        ),
        "fired on a file nothing starts"
    );

    assert!(
        !fired(
            &score_with_persistence(
                "C:\\Program Files\\Vendor\\shellext.dll",
                &image,
                PersistenceKind::ComServer
            ),
            feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE
        ),
        "an ordinary COM server registration bought the row"
    );

    let system = score_with_persistence(
        "C:\\Windows\\System32\\svcupdate.exe",
        &image,
        PersistenceKind::Service,
    );
    assert!(fired(&system, feature::NO_VERSION_RESOURCE), "{system:#?}");
    assert!(
        !fired(&system, feature::AUTOSTART_TARGET_WITHOUT_VERSION_RESOURCE),
        "the system zone took both rows: {system:#?}"
    );
}

fn score_with_persistence(file: &str, image: &[u8], kind: PersistenceKind) -> Vec<Evidence> {
    let p = path(file);
    let mut candidate = Candidate::new(CandidateId(0), REALISTIC_PRIOR);
    candidate.path = Some(p.clone());
    for observation in mm_harvest::pe::harvest(image, &p) {
        candidate.observe(observation);
    }
    candidate.observe(Observation::about_path(
        ArtifactSource::Registry { hive: "SYSTEM".into(), key: "Services\\vendorsvc".into() },
        p,
        ObservationKind::Persistence { kind, raw_value: file.to_string() },
    ));
    mm_score::extract(&candidate, &usable_baseline(), &Weights::embedded())
}

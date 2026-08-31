#![cfg(test)]

use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};
use mm_harvest::filesystem;
use mm_raw::Volume;

use crate::testimage::{Builder, Presence, ROOT_RECORD};

fn walk(volume: &Volume<std::io::Cursor<Vec<u8>>>) -> (Vec<String>, filesystem::WalkReport) {
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

fn javapath_volume() -> Volume<std::io::Cursor<Vec<u8>>> {
    let mut builder = Builder::new();
    let java = builder.directories(ROOT_RECORD, "Program Files\\Common Files\\Oracle\\Java");
    let target = builder.directory(java, "javapath_target_2175890");
    builder.resident_file(target, "java.exe", b"MZ the runtime", Presence::Live);
    builder.junction(
        java,
        "javapath",
        "\\??\\C:\\Program Files\\Common Files\\Oracle\\Java\\javapath_target_2175890",
    );
    builder.open()
}

#[test]
fn the_walk_alone_never_produces_the_path_through_a_junction() {
    let volume = javapath_volume();
    let (keys, report) = walk(&volume);

    let real = "\\program files\\common files\\oracle\\java\\javapath_target_2175890\\java.exe";
    let through = "\\program files\\common files\\oracle\\java\\javapath\\java.exe";
    assert!(keys.iter().any(|k| k == real), "the walk must find the file at its real path");
    assert!(
        !keys.iter().any(|k| k == through),
        "the walk reconstructs paths from the parent chain, so it cannot produce {through}"
    );
    assert_eq!(report.stats.unresolved, 0);
    assert_eq!(report.stats.unparsable, 0);
}

#[test]
fn the_walk_reports_the_junction_and_where_it_points() {
    let volume = javapath_volume();
    let (_, report) = walk(&volume);

    assert_eq!(report.stats.junctions_seen, 1);
    assert_eq!(report.stats.junctions_followed, 1);
    let junction = &report.junctions[0];
    assert_eq!(
        junction.at.as_deref(),
        Some("\\program files\\common files\\oracle\\java\\javapath")
    );
    assert_eq!(
        junction.target.as_deref(),
        Some("\\program files\\common files\\oracle\\java\\javapath_target_2175890")
    );
    assert_eq!(junction.refusal, None);
    assert_eq!(junction.tag, mm_raw::reparse::IO_REPARSE_TAG_MOUNT_POINT);
    assert!(junction.substitute.starts_with("\\??\\C:\\"));
}

#[test]
fn a_directory_symlink_resolves_too() {
    let mut builder = Builder::new();
    let apps = builder.directories(ROOT_RECORD, "Apps");
    let real = builder.directory(apps, "v2");
    builder.resident_file(real, "app.exe", b"MZ", Presence::Live);
    builder.directory_symlink(apps, "current", "\\??\\C:\\Apps\\v2", false);
    let volume = builder.open();

    let (_, report) = walk(&volume);
    assert_eq!(report.stats.junctions_followed, 1);
    let link = &report.junctions[0];
    assert_eq!(link.tag, mm_raw::reparse::IO_REPARSE_TAG_SYMLINK);
    assert_eq!(link.at.as_deref(), Some("\\apps\\current"));
    assert_eq!(link.target.as_deref(), Some("\\apps\\v2"));
}

#[test]
fn a_relative_symlink_resolves_against_its_own_directory() {
    let mut builder = Builder::new();
    let apps = builder.directories(ROOT_RECORD, "Apps");
    let real = builder.directory(apps, "v2");
    builder.resident_file(real, "app.exe", b"MZ", Presence::Live);
    builder.directory_symlink(apps, "current", "v2", true);
    let volume = builder.open();

    let (_, report) = walk(&volume);
    assert_eq!(report.junctions[0].target.as_deref(), Some("\\apps\\v2"));
}

#[test]
fn a_volume_mount_point_is_refused_and_says_why() {
    let mut builder = Builder::new();
    let data = builder.directories(ROOT_RECORD, "Data");
    builder.junction(data, "disk2", "\\??\\Volume{11111111-2222-3333-4444-555555555555}\\");
    let volume = builder.open();

    let (_, report) = walk(&volume);
    assert_eq!(report.stats.junctions_seen, 1);
    assert_eq!(report.stats.junctions_followed, 0);
    assert_eq!(report.junctions[0].target, None);
    assert!(report.junctions[0].refusal.is_some_and(|why| why.contains("mounted volume")));
}

#[test]
fn a_self_referential_junction_is_refused() {
    let mut builder = Builder::new();
    let pd = builder.directories(ROOT_RECORD, "ProgramData");
    builder.junction(pd, "loop", "\\??\\C:\\ProgramData\\loop");
    builder.junction(pd, "deeper", "\\??\\C:\\ProgramData\\deeper\\under");
    let volume = builder.open();

    let (_, report) = walk(&volume);
    assert_eq!(report.stats.junctions_seen, 2);
    assert_eq!(report.stats.junctions_followed, 0);
    for junction in &report.junctions {
        assert!(junction.refusal.is_some(), "{junction:?} must be refused");
    }
}

#[test]
fn a_malformed_reparse_point_is_ignored_rather_than_believed() {
    let mut builder = Builder::new();
    let data = builder.directories(ROOT_RECORD, "Data");
    builder.resident_file(data, "real.exe", b"MZ", Presence::Live);
    let mut content = mm_raw::reparse::IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes().to_vec();
    content.extend_from_slice(&0x0f00u16.to_le_bytes());
    content.extend_from_slice(&[0u8; 2]);
    content.extend_from_slice(&[0u8; 16]);
    builder.reparse_directory(data, "broken", &content);
    let volume = builder.open();

    let (keys, report) = walk(&volume);
    assert_eq!(report.stats.junctions_seen, 0, "a buffer we cannot read is not a link");
    assert!(keys.iter().any(|k| k == "\\data\\real.exe"), "the rest of the volume still walks");
}

#[test]
fn an_artifact_path_through_a_junction_joins_the_real_file() {
    let volume = javapath_volume();
    let (_, report) = walk(&volume);

    let through = "C:\\Program Files\\Common Files\\Oracle\\Java\\javapath\\java.exe";
    let mut observations = vec![Observation::about_path(
        ArtifactSource::Amcache,
        NormalizedPath::parse(through).unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    )];

    let mut coverage = mm_report::Coverage::default();
    crate::pipeline::canonicalize_through_junctions(
        &volume,
        &report.junctions,
        &mut observations,
        &mut coverage,
    );

    let real = "\\program files\\common files\\oracle\\java\\javapath_target_2175890\\java.exe";
    assert_eq!(
        observations[0].path.as_ref().unwrap().key(),
        real,
        "the artifact's spelling must be translated onto the path the filesystem holds"
    );
    assert!(
        observations.iter().any(|o| o.source == ArtifactSource::Mft
            && matches!(o.kind, ObservationKind::FileExists { .. })
            && o.path.as_ref().is_some_and(|p| p.key() == real)),
        "the translated path must carry the filesystem's answer, not silence: {observations:#?}"
    );
    let keys: std::collections::BTreeSet<&str> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key()).collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
}

#[test]
fn a_path_under_an_unfollowable_junction_is_named_in_the_coverage_section() {
    let mut builder = Builder::new();
    let data = builder.directories(ROOT_RECORD, "Data");
    builder.junction(data, "disk2", "\\??\\Volume{11111111-2222-3333-4444-555555555555}\\");
    let volume = builder.open();
    let (_, report) = walk(&volume);

    let mut observations = vec![Observation::about_path(
        ArtifactSource::Amcache,
        NormalizedPath::parse("C:\\Data\\disk2\\tool.exe").unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    )];
    let mut coverage = mm_report::Coverage::default();
    crate::pipeline::canonicalize_through_junctions(
        &volume,
        &report.junctions,
        &mut observations,
        &mut coverage,
    );

    assert_eq!(observations[0].path.as_ref().unwrap().key(), "\\data\\disk2\\tool.exe");
    assert!(
        coverage.warnings.iter().any(|w| w.contains("\\data\\disk2") && w.contains("UNKNOWN")),
        "{:#?}",
        coverage.warnings
    );
}

#[test]
fn a_junction_whose_target_is_not_here_leaves_the_key_alone() {
    let mut builder = Builder::new();
    let apps = builder.directories(ROOT_RECORD, "Apps");
    builder.junction(apps, "current", "\\??\\D:\\elsewhere\\v9");
    let volume = builder.open();
    let (_, report) = walk(&volume);
    assert_eq!(report.junctions[0].target.as_deref(), Some("\\elsewhere\\v9"));

    let mut observations = vec![Observation::about_path(
        ArtifactSource::Amcache,
        NormalizedPath::parse("C:\\Apps\\current\\app.exe").unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    )];
    let mut coverage = mm_report::Coverage::default();
    crate::pipeline::canonicalize_through_junctions(
        &volume,
        &report.junctions,
        &mut observations,
        &mut coverage,
    );

    assert_eq!(
        observations[0].path.as_ref().unwrap().key(),
        "\\apps\\current\\app.exe",
        "the volume did not confirm the translated path, so the key must not move"
    );
    assert!(
        observations.iter().all(|o| o.source != ArtifactSource::Mft),
        "and nothing may claim to have found the file"
    );
    assert!(
        coverage.warnings.iter().any(|w| w.contains("does not resolve") && w.contains("UNKNOWN")),
        "{:#?}",
        coverage.warnings
    );
}

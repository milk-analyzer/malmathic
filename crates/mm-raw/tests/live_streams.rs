#![cfg(windows)]

use mm_raw::Volume;

const USN_JOURNAL: &str = "\\$Extend\\$UsnJrnl";

const SAMPLE: usize = 64 * 1024;

fn live_volume() -> Option<Volume<std::fs::File>> {
    let file = std::fs::File::open(r"\\.\C:").ok()?;
    let volume = Volume::open(file, r"\\.\C:").ok()?;
    volume.is_windows_install().then_some(volume)
}

#[test]
fn a_named_stream_reads_from_a_real_volume() {
    let Some(volume) = live_volume() else { return };
    let Ok(journal) = volume.read_named_stream(USN_JOURNAL, "$J", SAMPLE) else {
        return;
    };
    assert!(!journal.is_empty(), "the $UsnJrnl:$J stream read as empty");
    assert!(journal.len() <= SAMPLE, "the byte cap was not enforced: {} bytes", journal.len());

    if let Ok(default) = volume.read_capped(USN_JOURNAL, SAMPLE) {
        assert_ne!(default, journal, "the named stream returned the default $DATA");
    }
}

#[test]
fn a_missing_stream_is_an_error_rather_than_silence() {
    let Some(volume) = live_volume() else { return };
    assert!(volume
        .read_named_stream("\\Windows\\System32\\ntoskrnl.exe", "Zone.Identifier", SAMPLE)
        .is_err());
    assert!(volume.read_named_stream("\\no\\such\\file.txt", "$J", SAMPLE).is_err());
}

#[test]
fn a_real_mark_of_the_web_reads_and_parses() {
    let Some(volume) = live_volume() else { return };

    let mut found = 0usize;
    for user in volume.list_directory("\\Users") {
        let downloads = format!("\\Users\\{user}\\Downloads");
        for name in volume.list_directory(&downloads).into_iter().take(200) {
            let path = format!("{downloads}\\{name}");
            let Ok(bytes) = volume.read_named_stream(&path, "Zone.Identifier", 64 * 1024) else {
                continue;
            };
            found += 1;
            assert!(
                bytes.len() < 4096,
                "a Zone.Identifier of {} bytes is not what Windows writes",
                bytes.len()
            );
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.to_ascii_lowercase().contains("zonetransfer"),
                "read something that is not a Mark of the Web from {path}: {text:?}"
            );
        }
    }
    eprintln!("{found} Zone.Identifier stream(s) read from Downloads folders");
}

#[test]
fn the_volume_was_actually_readable() {
    let Some(volume) = live_volume() else { return };
    assert!(
        !volume.list_directory("\\Users").is_empty(),
        "the volume opened but \\Users enumerated as empty"
    );
    assert!(volume.exists("\\Windows\\System32\\ntoskrnl.exe"));
}

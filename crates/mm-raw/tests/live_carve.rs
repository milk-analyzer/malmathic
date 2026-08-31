#![cfg(windows)]

use std::io::Write;

use mm_raw::Volume;

const BITMAP_RECORD: u64 = 6;

const SETTLE_ATTEMPTS: usize = 40;
const SETTLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

fn live_volume() -> Option<Volume<std::fs::File>> {
    let file = std::fs::File::open(r"\\.\C:").ok()?;
    let volume = Volume::open(file, r"\\.\C:").ok()?;
    volume.is_windows_install().then_some(volume)
}

fn volume_relative(path: &std::path::Path) -> Option<String> {
    let text = path.to_str()?;
    let rest = text.strip_prefix("C:")?;
    Some(rest.to_string())
}

fn settle(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..SETTLE_ATTEMPTS {
        if predicate() {
            return true;
        }
        std::thread::sleep(SETTLE_INTERVAL);
    }
    false
}

fn sample() -> Vec<u8> {
    let mut bytes = b"malmathic live carve fixture v1 ".to_vec();
    let mut x: u32 = 0x1234_5678;
    while bytes.len() < 40_000 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes
}

#[test]
fn a_file_this_test_deleted_is_carved_back_byte_for_byte() {
    let Some(volume) = live_volume() else {
        eprintln!("skipped: \\\\.\\C: could not be opened (needs Administrator)");
        return;
    };

    let directory = std::env::temp_dir().join("malmathic-carve-fixture");
    if std::fs::create_dir_all(&directory).is_err() {
        eprintln!("skipped: could not create a scratch directory");
        return;
    }
    let path = directory.join(format!("carve-me-{}.bin", std::process::id()));
    let Some(key) = volume_relative(&path) else {
        eprintln!("skipped: the temp directory is not on C:");
        return;
    };

    let content = sample();
    {
        let Ok(mut file) = std::fs::File::create(&path) else {
            eprintln!("skipped: could not create the fixture file");
            return;
        };
        assert!(file.write_all(&content).is_ok());
        assert!(file.sync_all().is_ok());
    }

    if !settle(|| volume.exists(&key)) {
        let _ = std::fs::remove_file(&path);
        eprintln!("skipped: the new file did not reach the volume within the settle budget");
        return;
    }
    let record = volume.resolve(&key).expect("the file resolves once it is visible");

    let before = volume.read_capped(&key, 1 << 20).expect("the live file reads");
    assert_eq!(before, content, "the file did not reach the volume intact");

    assert!(std::fs::remove_file(&path).is_ok());

    if !settle(|| volume.record_identity(record).is_some_and(|i| !i.in_use)) {
        eprintln!("skipped: the deletion did not reach the volume within the settle budget");
        return;
    }

    let identity = volume.record_identity(record).expect("the record survives its file");
    assert!(!identity.in_use, "the record is still marked in use after a delete");
    assert_eq!(
        identity.name,
        path.file_name().unwrap().to_string_lossy(),
        "the deleted record no longer carries the file's name"
    );
    assert_eq!(identity.size, content.len() as u64);

    assert!(!volume.exists(&key), "the deleted path still resolves");

    let carved = volume.read_record_capped(record, 1 << 20).expect("the clusters read back");
    assert_eq!(carved, content, "the carved bytes are not the file");

    let runs = volume.fs().runs_by_record(record, None).expect("the runlist decodes");
    assert!(!runs.is_empty(), "a 40 KB file should not have a resident $DATA");
    if let Ok(bitmap) = volume.read_record_capped(BITMAP_RECORD, 128 * 1024 * 1024) {
        let mut allocated = 0usize;
        let mut total = 0usize;
        for run in &runs {
            let Some(lcn) = run.lcn else { continue };
            for cluster in lcn..lcn + run.length {
                total += 1;
                let byte = (cluster / 8) as usize;
                if bitmap.get(byte).is_some_and(|b| b & (1 << (cluster % 8)) != 0) {
                    allocated += 1;
                }
            }
        }
        assert!(total > 0, "the runlist covered no clusters");
        eprintln!("carved {} bytes; {allocated} of {total} clusters still allocated", carved.len());
        assert_eq!(
            allocated, 0,
            "the deleted file's clusters are still marked allocated in $Bitmap, which would make \
             every carve on this machine report PARTIAL"
        );
    }

    let _ = std::fs::remove_dir(&directory);
}

#[test]
fn the_volume_was_actually_readable() {
    let Some(volume) = live_volume() else { return };
    assert!(volume.exists("\\Windows\\System32\\ntoskrnl.exe"));
    let record = volume.resolve("\\Windows\\System32\\ntoskrnl.exe").expect("ntoskrnl resolves");
    let identity = volume.record_identity(record).expect("its record identifies itself");
    assert!(identity.in_use, "a live system file read as deleted");
    assert!(identity.name.eq_ignore_ascii_case("ntoskrnl.exe"), "got {}", identity.name);
    assert!(identity.size > 1_000_000, "ntoskrnl.exe read as {} bytes", identity.size);
}

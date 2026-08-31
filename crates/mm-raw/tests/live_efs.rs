#![cfg(windows)]

use std::os::windows::fs::MetadataExt;

use mm_raw::Volume;

const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

const SAMPLE: usize = 400;

const WHERE_TO_LOOK: [&str; 3] = ["\\Windows\\System32", "\\Windows\\SysWOW64", "\\Program Files"];

fn live_volume() -> Option<Volume<std::fs::File>> {
    let file = std::fs::File::open(r"\\.\C:").ok()?;
    let volume = Volume::open(file, r"\\.\C:").ok()?;
    volume.is_windows_install().then_some(volume)
}

#[test]
fn the_raw_reader_and_windows_agree_about_which_files_are_encrypted() {
    let Some(volume) = live_volume() else { return };

    let mut compared = 0usize;
    let mut disagreements: Vec<String> = Vec::new();

    for directory in WHERE_TO_LOOK {
        for name in volume.list_directory(directory) {
            if compared >= SAMPLE {
                break;
            }
            let key = format!("{directory}\\{name}");

            let Ok(metadata) = std::fs::metadata(format!("C:{key}")) else { continue };
            if !metadata.is_file() {
                continue;
            }
            let windows_says = metadata.file_attributes() & FILE_ATTRIBUTE_ENCRYPTED != 0;

            let Some(record) = volume.resolve(&key) else { continue };
            let we_say = volume.is_efs_encrypted(record);

            compared += 1;
            if windows_says != we_say {
                disagreements.push(format!(
                    "{key}: Windows says encrypted={windows_says}, the MFT reader says {we_say}"
                ));
            }
        }
    }

    assert!(
        compared > 0,
        "the volume opened but no file was compared — this test would have passed without \
         checking anything, which is the one outcome it must not have"
    );
    assert!(
        disagreements.is_empty(),
        "the raw reader and Windows disagree about {} of {compared} files:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

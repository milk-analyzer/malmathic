use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use mm_core::{Error, Result};
use mm_raw::{classify, Volume, VolumeKind};
use ntfs_core::OffsetReader;

use crate::readonly::ReadOnlyFile;
use crate::vdi::Vdi;
use crate::vmdk::Vmdk;

#[derive(Debug)]
pub enum ImageFile {
    Raw(ReadOnlyFile),
    Vdi(Box<Vdi>),
    Vmdk(Box<Vmdk>),
}

impl ImageFile {
    pub fn open(path: &Path) -> Result<Self> {
        if Vmdk::looks_like_one(path) {
            let vmdk = Vmdk::open(path)
                .map_err(|e| Error::io(format!("opening VMDK {}", path.display()), e))?;
            return Ok(ImageFile::Vmdk(Box::new(vmdk)));
        }
        if Vdi::looks_like_one(path) {
            let vdi = Vdi::open(path)
                .map_err(|e| Error::io(format!("opening VDI {}", path.display()), e))?;
            return Ok(ImageFile::Vdi(Box::new(vdi)));
        }
        let file = ReadOnlyFile::open(path)
            .map_err(|e| Error::io(format!("opening image {}", path.display()), e))?;
        Ok(ImageFile::Raw(file))
    }

    pub fn disk_size(&self, path: &Path) -> Result<u64> {
        match self {
            ImageFile::Raw(file) => {
                file.len().map_err(|e| Error::io(format!("sizing image {}", path.display()), e))
            }
            ImageFile::Vdi(vdi) => Ok(vdi.disk_size()),
            ImageFile::Vmdk(vmdk) => Ok(vmdk.disk_size()),
        }
    }
}

impl Read for ImageFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ImageFile::Raw(file) => file.read(buf),
            ImageFile::Vdi(vdi) => vdi.read(buf),
            ImageFile::Vmdk(vmdk) => vmdk.read(buf),
        }
    }
}

impl Seek for ImageFile {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        match self {
            ImageFile::Raw(file) => file.seek(to),
            ImageFile::Vdi(vdi) => vdi.seek(to),
            ImageFile::Vmdk(vmdk) => vmdk.seek(to),
        }
    }
}

const SECTOR: u64 = 512;

const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const MBR_PARTITION_TABLE_OFFSET: usize = 0x1BE;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_ENTRY_COUNT: usize = 4;
const MBR_TYPE_NTFS: u8 = 0x07;
const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_MAX_ENTRIES: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub offset: u64,
    pub length: u64,
}

pub type ImageVolume = Volume<OffsetReader<ImageFile>>;

pub fn find_ntfs_partitions(path: &Path) -> Result<Vec<Partition>> {
    let mut file = ImageFile::open(path)?;
    let length = file.disk_size(path)?;

    let mut first = [0u8; 512];
    file.read_exact(&mut first)
        .map_err(|e| Error::io(format!("reading the first sector of {}", path.display()), e))?;

    if classify(&first) == VolumeKind::Ntfs {
        return Ok(vec![Partition { offset: 0, length }]);
    }

    if first[510..512] != MBR_SIGNATURE {
        return Err(Error::parse(format!(
            "{} is neither an NTFS volume nor a partitioned disk image",
            path.display()
        )));
    }

    let entries = parse_mbr(&first);
    if entries.iter().any(|e| e.gpt_protective) {
        return parse_gpt(&mut file, length);
    }

    Ok(entries
        .into_iter()
        .filter(|e| e.kind == MBR_TYPE_NTFS)
        .map(|e| Partition {
            offset: e.start_lba.saturating_mul(SECTOR),
            length: e.sector_count.saturating_mul(SECTOR),
        })
        .filter(|p| p.length > 0 && p.offset < length)
        .collect())
}

pub fn open_partition(path: &Path, partition: Partition) -> Result<ImageVolume> {
    let file = ImageFile::open(path)?;

    let reader = OffsetReader::new(file, partition.offset, partition.length)
        .map_err(|e| Error::parse(format!("windowing the image at {}: {e}", partition.offset)))?;

    Volume::open(reader, &format!("{}@{}", path.display(), partition.offset))
}

struct MbrEntry {
    kind: u8,
    start_lba: u64,
    sector_count: u64,
    gpt_protective: bool,
}

fn parse_mbr(sector: &[u8; 512]) -> Vec<MbrEntry> {
    (0..MBR_ENTRY_COUNT)
        .filter_map(|i| {
            let at = MBR_PARTITION_TABLE_OFFSET + i * MBR_ENTRY_SIZE;
            let entry = sector.get(at..at + MBR_ENTRY_SIZE)?;
            let kind = entry[4];
            if kind == 0 {
                return None;
            }
            Some(MbrEntry {
                kind,
                start_lba: u64::from(u32::from_le_bytes(entry[8..12].try_into().ok()?)),
                sector_count: u64::from(u32::from_le_bytes(entry[12..16].try_into().ok()?)),
                gpt_protective: kind == MBR_TYPE_GPT_PROTECTIVE,
            })
        })
        .collect()
}

fn parse_gpt(file: &mut ImageFile, image_length: u64) -> Result<Vec<Partition>> {
    let mut header = [0u8; 512];
    file.seek(SeekFrom::Start(SECTOR)).map_err(|e| Error::io("seeking to the GPT header", e))?;
    file.read_exact(&mut header).map_err(|e| Error::io("reading the GPT header", e))?;

    if &header[0..8] != GPT_SIGNATURE {
        return Err(Error::parse("the protective MBR is not followed by a GPT header"));
    }

    let entries_lba = u64::from_le_bytes(header[72..80].try_into().unwrap_or_default());
    let entry_count = u32::from_le_bytes(header[80..84].try_into().unwrap_or_default());
    let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap_or_default());

    if entry_count == 0 || entry_count > GPT_MAX_ENTRIES || !(128..=4096).contains(&entry_size) {
        return Err(Error::parse(format!(
            "the GPT header declares {entry_count} entries of {entry_size} bytes, which is not credible"
        )));
    }

    let mut found = Vec::new();
    for index in 0..entry_count {
        let at = entries_lba
            .saturating_mul(SECTOR)
            .saturating_add(u64::from(index) * u64::from(entry_size));
        if at >= image_length {
            break;
        }

        let mut entry = vec![0u8; entry_size as usize];
        if file.seek(SeekFrom::Start(at)).is_err() || file.read_exact(&mut entry).is_err() {
            break;
        }
        if entry[0..16].iter().all(|b| *b == 0) {
            continue;
        }

        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap_or_default());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap_or_default());
        if last_lba < first_lba {
            continue;
        }

        let offset = first_lba.saturating_mul(SECTOR);
        let length = (last_lba - first_lba + 1).saturating_mul(SECTOR);
        if offset >= image_length {
            continue;
        }

        let mut boot = [0u8; 512];
        if file.seek(SeekFrom::Start(offset)).is_err() || file.read_exact(&mut boot).is_err() {
            continue;
        }
        if classify(&boot) == VolumeKind::Ntfs {
            found.push(Partition { offset, length });
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn temp_image(bytes: &[u8]) -> (tempdir::Dir, std::path::PathBuf) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("image.dd");
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        (dir, path)
    }

    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static NEXT: AtomicU32 = AtomicU32::new(0);
                let base = std::env::temp_dir().join(format!(
                    "malmathic-image-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                let _ = std::fs::create_dir_all(&base);
                Dir(base)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn ntfs_boot_sector() -> [u8; 512] {
        let mut s = [0u8; 512];
        s[3..11].copy_from_slice(b"NTFS    ");
        s
    }

    fn mbr_with(entries: &[(u8, u32, u32)]) -> [u8; 512] {
        let mut s = [0u8; 512];
        for (i, (kind, start, count)) in entries.iter().enumerate() {
            let at = MBR_PARTITION_TABLE_OFFSET + i * MBR_ENTRY_SIZE;
            s[at + 4] = *kind;
            s[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            s[at + 12..at + 16].copy_from_slice(&count.to_le_bytes());
        }
        s[510..512].copy_from_slice(&MBR_SIGNATURE);
        s
    }

    #[test]
    fn a_bare_volume_image_is_recognized() {
        let (_d, path) = temp_image(&ntfs_boot_sector());
        let parts = find_ntfs_partitions(&path).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].offset, 0);
    }

    #[test]
    fn mbr_ntfs_partitions_are_located() {
        let mut image = mbr_with(&[(MBR_TYPE_NTFS, 2048, 1000), (0x0C, 4096, 1000)]).to_vec();
        image.resize(4 * 1024 * 1024, 0);
        let (_d, path) = temp_image(&image);

        let parts = find_ntfs_partitions(&path).unwrap();
        assert_eq!(parts.len(), 1, "only the NTFS entry should be returned");
        assert_eq!(parts[0].offset, 2048 * SECTOR);
        assert_eq!(parts[0].length, 1000 * SECTOR);
    }

    #[test]
    fn empty_mbr_slots_are_skipped() {
        let mut image = mbr_with(&[(0, 0, 0), (MBR_TYPE_NTFS, 128, 64)]).to_vec();
        image.resize(1024 * 1024, 0);
        let (_d, path) = temp_image(&image);
        assert_eq!(find_ntfs_partitions(&path).unwrap().len(), 1);
    }

    #[test]
    fn an_implausible_gpt_header_is_rejected() {
        let mut image = mbr_with(&[(MBR_TYPE_GPT_PROTECTIVE, 1, 0xFFFF_FFFF)]).to_vec();
        image.resize(1024 * 1024, 0);
        image[512..520].copy_from_slice(GPT_SIGNATURE);
        image[512 + 80..512 + 84].copy_from_slice(&u32::MAX.to_le_bytes());
        image[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());

        let (_d, path) = temp_image(&image);
        let err = find_ntfs_partitions(&path).unwrap_err();
        assert!(err.to_string().contains("not credible"), "got {err}");
    }

    #[test]
    fn a_file_that_is_neither_is_refused_clearly() {
        let (_d, path) = temp_image(&[0u8; 512]);
        let err = find_ntfs_partitions(&path).unwrap_err();
        assert!(err.to_string().contains("neither an NTFS volume nor a partitioned"), "got {err}");
    }

    #[test]
    fn a_missing_file_reports_itself() {
        let err = find_ntfs_partitions(Path::new("no-such-image.dd")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
    }

    #[test]
    fn a_truncated_image_errors_cleanly() {
        let (_d, path) = temp_image(&[0u8; 16]);
        assert!(find_ntfs_partitions(&path).is_err());
    }
}

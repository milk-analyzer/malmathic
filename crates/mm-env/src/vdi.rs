use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::path::Path;

use crate::readonly::ReadOnlyFile;

const SIGNATURE: u32 = 0xBEDA_107F;

const UNALLOCATED: u32 = 0xFFFF_FFFF;
const ZERO_BLOCK: u32 = 0xFFFF_FFFE;

const MAX_BLOCKS: usize = 16 * 1024 * 1024;

const MAX_BLOCK_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Vdi {
    file: ReadOnlyFile,
    map: Vec<u32>,
    block_size: u64,
    block_extra: u64,
    data_offset: u64,
    disk_size: u64,
    pos: u64,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or_default())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default())
}

impl Vdi {
    pub fn looks_like_one(path: &Path) -> bool {
        let mut file = match ReadOnlyFile::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut header = [0u8; 0x200];
        file.read_exact(&mut header).is_ok() && le32(&header, 0x40) == SIGNATURE
    }

    pub fn open(path: &Path) -> Result<Self> {
        let mut file = ReadOnlyFile::open(path)?;
        let mut header = [0u8; 0x200];
        file.read_exact(&mut header)?;
        if le32(&header, 0x40) != SIGNATURE {
            return Err(Error::new(ErrorKind::InvalidData, "not a VDI image"));
        }

        let blocks_offset = u64::from(le32(&header, 0x154));
        let data_offset = u64::from(le32(&header, 0x158));
        let disk_size = le64(&header, 0x170);
        let block_size = u64::from(le32(&header, 0x178));
        let block_extra = u64::from(le32(&header, 0x17C));
        let blocks = le32(&header, 0x180) as usize;

        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("the VDI header declares a {block_size}-byte block, which is not credible"),
            ));
        }
        if blocks == 0 || blocks > MAX_BLOCKS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("the VDI header declares {blocks} blocks, which is not credible"),
            ));
        }

        let mut raw = vec![0u8; blocks * 4];
        file.seek(SeekFrom::Start(blocks_offset))?;
        file.read_exact(&mut raw)?;
        let map = (0..blocks).map(|i| le32(&raw, i * 4)).collect();

        Ok(Vdi { file, map, block_size, block_extra, data_offset, disk_size, pos: 0 })
    }

    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }
}

impl Read for Vdi {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pos >= self.disk_size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((self.disk_size - self.pos) as usize);
        let index = (self.pos / self.block_size) as usize;
        let within = self.pos % self.block_size;
        let n = want.min((self.block_size - within) as usize);

        match self.map.get(index).copied() {
            Some(UNALLOCATED) | Some(ZERO_BLOCK) | None => buf[..n].fill(0),
            Some(physical) => {
                let at = self
                    .data_offset
                    .checked_add(
                        u64::from(physical)
                            .checked_mul(self.block_size + self.block_extra)
                            .ok_or_else(|| {
                                Error::new(ErrorKind::InvalidData, "VDI block index overflows")
                            })?,
                    )
                    .and_then(|a| a.checked_add(self.block_extra + within))
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidData, "VDI block offset overflows")
                    })?;
                self.file.seek(SeekFrom::Start(at))?;
                self.file.read_exact(&mut buf[..n])?;
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Vdi {
    fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        let next = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.disk_size.checked_add_signed(n),
            SeekFrom::Current(n) => self.pos.checked_add_signed(n),
        };
        match next {
            Some(n) => {
                self.pos = n;
                Ok(n)
            }
            None => Err(Error::new(ErrorKind::InvalidInput, "seek before the start of the disk")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn fixture(block_size: u32) -> (std::path::PathBuf, Vec<u8>) {
        let payload: Vec<u8> = (0..block_size).map(|i| (i % 251) as u8).collect();
        let blocks_offset: u32 = 0x200;
        let data_offset: u32 = 0x400;
        let mut file = vec![0u8; data_offset as usize];
        file[0x40..0x44].copy_from_slice(&SIGNATURE.to_le_bytes());
        file[0x154..0x158].copy_from_slice(&blocks_offset.to_le_bytes());
        file[0x158..0x15C].copy_from_slice(&data_offset.to_le_bytes());
        file[0x170..0x178].copy_from_slice(&(u64::from(block_size) * 3).to_le_bytes());
        file[0x178..0x17C].copy_from_slice(&block_size.to_le_bytes());
        file[0x17C..0x180].copy_from_slice(&0u32.to_le_bytes());
        file[0x180..0x184].copy_from_slice(&3u32.to_le_bytes());
        let map = [0u32, UNALLOCATED, ZERO_BLOCK];
        for (i, entry) in map.iter().enumerate() {
            let at = blocks_offset as usize + i * 4;
            file[at..at + 4].copy_from_slice(&entry.to_le_bytes());
        }
        file.extend_from_slice(&payload);

        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "mm-env-vdi-{}-{}.vdi",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut f = File::create(&path).expect("a fixture");
        f.write_all(&file).expect("writing the fixture");
        (path, payload)
    }

    #[test]
    fn an_allocated_block_reads_back_byte_for_byte() {
        let (path, payload) = fixture(4096);
        assert!(Vdi::looks_like_one(&path));
        let mut vdi = Vdi::open(&path).expect("opening the fixture");
        let mut got = vec![0u8; 4096];
        vdi.read_exact(&mut got).expect("reading block 0");
        assert_eq!(got, payload);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unwritten_and_discarded_blocks_read_as_zeroes_rather_than_seeking() {
        let (path, _) = fixture(4096);
        let mut vdi = Vdi::open(&path).expect("opening the fixture");
        for block in [1u64, 2] {
            vdi.seek(SeekFrom::Start(block * 4096)).expect("seeking");
            let mut got = vec![0xAAu8; 4096];
            vdi.read_exact(&mut got).expect("reading a hole");
            assert!(got.iter().all(|b| *b == 0), "block {block} should read as zeroes");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_read_across_a_block_boundary_is_split_and_still_complete() {
        let (path, payload) = fixture(4096);
        let mut vdi = Vdi::open(&path).expect("opening the fixture");
        vdi.seek(SeekFrom::Start(4096 - 16)).expect("seeking");
        let mut got = vec![0xAAu8; 32];
        vdi.read_exact(&mut got).expect("reading across the boundary");
        assert_eq!(&got[..16], &payload[4096 - 16..]);
        assert!(got[16..].iter().all(|b| *b == 0), "the second half is a hole");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reading_past_the_end_of_the_disk_returns_nothing() {
        let (path, _) = fixture(4096);
        let mut vdi = Vdi::open(&path).expect("opening the fixture");
        vdi.seek(SeekFrom::Start(4096 * 3)).expect("seeking to the end");
        assert_eq!(vdi.read(&mut [0u8; 16]).expect("a read past the end"), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_header_that_is_not_a_vdi_is_refused() {
        let path =
            std::env::temp_dir().join(format!("mm-env-not-a-vdi-{}.bin", std::process::id()));
        std::fs::write(&path, vec![0u8; 0x400]).expect("a fixture");
        assert!(!Vdi::looks_like_one(&path));
        assert!(Vdi::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_implausible_header_is_refused_rather_than_allocated() {
        let path = std::env::temp_dir().join(format!("mm-env-huge-vdi-{}.bin", std::process::id()));
        let mut file = vec![0u8; 0x400];
        file[0x40..0x44].copy_from_slice(&SIGNATURE.to_le_bytes());
        file[0x178..0x17C].copy_from_slice(&4096u32.to_le_bytes());
        file[0x180..0x184].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &file).expect("a fixture");
        assert!(Vdi::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}

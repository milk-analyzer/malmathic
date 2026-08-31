#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub const SECTOR: usize = 512;

pub mod at {
    pub const MAGIC: usize = 0x00;
    pub const VERSION: usize = 0x04;
    pub const FLAGS: usize = 0x08;
    pub const CAPACITY: usize = 0x0C;
    pub const GRAIN_SIZE: usize = 0x14;
    pub const DESCRIPTOR_OFFSET: usize = 0x1C;
    pub const DESCRIPTOR_SIZE: usize = 0x24;
    pub const GTE_PER_GT: usize = 0x2C;
    pub const RGD_OFFSET: usize = 0x30;
    pub const GD_OFFSET: usize = 0x38;
    pub const OVERHEAD: usize = 0x40;
    pub const NEWLINE_CANARY: usize = 0x49;
    pub const COMPRESS: usize = 0x4D;
}

pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mm-env-hostile-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&dir);
        Scratch(dir)
    }

    pub fn dir(&self) -> &Path {
        &self.0
    }

    pub fn put(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).expect("writing a fixture");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub const GRAIN_SECTORS: u64 = 8;
pub const GTE_PER_GT: u32 = 4;
pub const CAPACITY_SECTORS: u64 = 64;
pub const DESCRIPTOR_SECTORS: u64 = 4;

const GD_SECTOR: u64 = 1 + DESCRIPTOR_SECTORS;
const GT0_SECTOR: u64 = GD_SECTOR + 1;
const GT_COUNT: u64 = 2;
const DATA_SECTOR: u64 = GT0_SECTOR + GT_COUNT;

pub struct Forge {
    pub descriptor: String,
    grains: Vec<(usize, Vec<u8>)>,
}

impl Forge {
    pub fn new(descriptor: impl Into<String>) -> Self {
        Forge { descriptor: descriptor.into(), grains: Vec::new() }
    }

    pub fn grain(mut self, index: usize, byte: u8) -> Self {
        self.grains.push((index, vec![byte; (GRAIN_SECTORS as usize) * SECTOR]));
        self
    }

    pub fn grain_bytes(mut self, index: usize, bytes: &[u8]) -> Self {
        let mut g = vec![0u8; (GRAIN_SECTORS as usize) * SECTOR];
        let n = bytes.len().min(g.len());
        g[..n].copy_from_slice(&bytes[..n]);
        self.grains.push((index, g));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut file = vec![0u8; (DATA_SECTOR as usize) * SECTOR];

        file[at::MAGIC..at::MAGIC + 4].copy_from_slice(b"KDMV");
        put32(&mut file, at::VERSION, 1);
        put32(&mut file, at::FLAGS, 1);
        put64(&mut file, at::CAPACITY, CAPACITY_SECTORS);
        put64(&mut file, at::GRAIN_SIZE, GRAIN_SECTORS);
        put64(&mut file, at::DESCRIPTOR_OFFSET, 1);
        put64(&mut file, at::DESCRIPTOR_SIZE, DESCRIPTOR_SECTORS);
        put32(&mut file, at::GTE_PER_GT, GTE_PER_GT);
        put64(&mut file, at::RGD_OFFSET, 0);
        put64(&mut file, at::GD_OFFSET, GD_SECTOR);
        put64(&mut file, at::OVERHEAD, DATA_SECTOR);
        file[at::NEWLINE_CANARY] = b'\n';
        file[at::NEWLINE_CANARY + 1] = b' ';
        file[at::NEWLINE_CANARY + 2] = b'\r';
        file[at::NEWLINE_CANARY + 3] = b'\n';

        let d = self.descriptor.as_bytes();
        let start = SECTOR;
        let room = (DESCRIPTOR_SECTORS as usize) * SECTOR;
        let n = d.len().min(room);
        file[start..start + n].copy_from_slice(&d[..n]);

        for t in 0..GT_COUNT {
            let off = (GD_SECTOR as usize) * SECTOR + (t as usize) * 4;
            put32(&mut file, off, (GT0_SECTOR + t) as u32);
        }

        let mut next = DATA_SECTOR;
        for (index, bytes) in &self.grains {
            let table = *index / GTE_PER_GT as usize;
            let slot = *index % GTE_PER_GT as usize;
            let gt = GT0_SECTOR + table as u64;
            put32(&mut file, (gt as usize) * SECTOR + slot * 4, next as u32);
            file.resize((next as usize) * SECTOR, 0);
            file.extend_from_slice(bytes);
            next += GRAIN_SECTORS;
        }
        file
    }
}

pub fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn get32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

pub fn grain_table_entry(index: usize) -> usize {
    let table = index / GTE_PER_GT as usize;
    let slot = index % GTE_PER_GT as usize;
    ((GT0_SECTOR + table as u64) as usize) * SECTOR + slot * 4
}

pub fn grain_directory_entry(index: usize) -> usize {
    (GD_SECTOR as usize) * SECTOR + index * 4
}

pub fn ntfs_boot_sector() -> Vec<u8> {
    let mut s = vec![0u8; SECTOR];
    s[3..11].copy_from_slice(b"NTFS    ");
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

pub fn base_descriptor(name: &str) -> String {
    format!(
        "# Disk DescriptorFile\nversion=1\nencoding=\"windows-1251\"\nCID=aaaaaaaa\n\
         parentCID=ffffffff\ncreateType=\"monolithicSparse\"\n\n# Extent description\n\
         RW {CAPACITY_SECTORS} SPARSE \"{name}\"\n\n# The Disk Data Base \n#DDB\n\
         ddb.adapterType = \"lsilogic\"\n"
    )
}

pub fn delta_descriptor(name: &str, parent: &str, cid: &str, parent_cid: &str) -> String {
    format!(
        "# Disk DescriptorFile\nversion=1\nCID={cid}\nparentCID={parent_cid}\n\
         createType=\"monolithicSparse\"\nparentFileNameHint=\"{parent}\"\n\n\
         RW {CAPACITY_SECTORS} SPARSE \"{name}\"\n"
    )
}

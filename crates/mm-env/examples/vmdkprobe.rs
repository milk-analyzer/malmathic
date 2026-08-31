use mm_env::vmdk::{Provenance, Vmdk};
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

fn main() {
    for arg in std::env::args().skip(1) {
        let path = std::path::Path::new(&arg);
        println!("### {}", path.display());
        let mut v = match Vmdk::open(path) {
            Ok(v) => v,
            Err(e) => {
                println!("    REFUSED: {e}\n");
                continue;
            }
        };
        let info = v.info().clone();
        println!("    {}", info.summary());
        for (i, l) in info.chain.iter().enumerate() {
            println!(
                "      [{i}] {:<34} CID={:<9} parentCID={:<9} extents={}",
                l.name, l.cid, l.parent_cid, l.extents
            );
        }
        let mut mbr = [0u8; 512];
        v.seek(SeekFrom::Start(0)).unwrap();
        v.read_exact(&mut mbr).unwrap();
        println!("    LBA0 tail = {:02x}{:02x}", mbr[510], mbr[511]);
        for i in 0..4 {
            let e = &mbr[0x1BE + i * 16..0x1BE + i * 16 + 16];
            if e[4] == 0 {
                continue;
            }
            let start = u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64;
            let count = u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64;
            let mut bs = [0u8; 512];
            v.seek(SeekFrom::Start(start * 512)).unwrap();
            v.read_exact(&mut bs).unwrap();
            let prov = v.provenance(start * 512).unwrap();
            println!(
                "    part{i} type=0x{:02x} start={start} sectors={count} oem={:?} from={}",
                e[4],
                String::from_utf8_lossy(&bs[3..11]),
                match prov {
                    Provenance::Stored { name, .. } => name,
                    Provenance::NeverWritten => "NEVER WRITTEN".into(),
                    Provenance::ExplicitlyZeroed { name, .. } => format!("zeroed by {name}"),
                    Provenance::PastEnd => "past end".into(),
                }
            );
        }
        let t = Instant::now();
        let mut buf = [0u8; 1024];
        let base = 104448u64 * 512;
        for i in 0..200_000u64 {
            v.seek(SeekFrom::Start(base + i * 1024)).unwrap();
            let _ = v.read(&mut buf).unwrap();
        }
        let el = t.elapsed();
        let c = v.cache_cost();
        println!("    200k x 1KiB hops in {:?}  ({:.0} reads/s); GT cache hits={} misses={} evictions={}",
                 el, 200_000.0 / el.as_secs_f64(), c.hits, c.misses, c.evictions);
        println!();
    }
}

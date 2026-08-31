use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const BLOCK_SIZE: u64 = 128 * 1024;
const BLOCK_COUNT: usize = 8;

struct CacheBlock {
    start: u64,
    data: Vec<u8>,
    valid: bool,
}

#[derive(Debug, Default)]
pub struct CacheCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    conflicts: AtomicU64,
    device_reads: AtomicU64,
    device_bytes: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub conflicts: u64,
    pub device_reads: u64,
    pub device_bytes: u64,
}

impl CacheCounters {
    pub fn snapshot(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            conflicts: self.conflicts.load(Ordering::Relaxed),
            device_reads: self.device_reads.load(Ordering::Relaxed),
            device_bytes: self.device_bytes.load(Ordering::Relaxed),
        }
    }
}

impl CacheStats {
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.hits + self.misses;
        (total > 0).then(|| self.hits as f64 / total as f64)
    }

    pub fn since(&self, earlier: CacheStats) -> CacheStats {
        CacheStats {
            hits: self.hits.saturating_sub(earlier.hits),
            misses: self.misses.saturating_sub(earlier.misses),
            conflicts: self.conflicts.saturating_sub(earlier.conflicts),
            device_reads: self.device_reads.saturating_sub(earlier.device_reads),
            device_bytes: self.device_bytes.saturating_sub(earlier.device_bytes),
        }
    }
}

pub struct BlockReader<D: BlockDevice> {
    device: D,
    length: u64,
    position: u64,
    cache: Vec<CacheBlock>,
    counters: Arc<CacheCounters>,
}

pub trait BlockDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn length(&self) -> u64;
}

impl<D: BlockDevice> BlockReader<D> {
    pub fn new(device: D) -> Self {
        Self::with_block_count(device, BLOCK_COUNT)
    }

    pub fn with_block_count(device: D, blocks: usize) -> Self {
        let length = device.length();
        let cache = (0..blocks.max(1))
            .map(|_| CacheBlock { start: 0, data: Vec::new(), valid: false })
            .collect();
        BlockReader { device, length, position: 0, cache, counters: Arc::default() }
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn counters(&self) -> Arc<CacheCounters> {
        Arc::clone(&self.counters)
    }

    fn load(&mut self, block_start: u64) -> io::Result<usize> {
        let slot = ((block_start / BLOCK_SIZE) as usize) % self.cache.len();
        if self.cache[slot].valid && self.cache[slot].start == block_start {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(slot);
        }
        self.counters.misses.fetch_add(1, Ordering::Relaxed);
        if self.cache[slot].valid {
            self.counters.conflicts.fetch_add(1, Ordering::Relaxed);
        }

        let want = BLOCK_SIZE.min(self.length.saturating_sub(block_start)) as usize;
        if want == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end of volume"));
        }

        let got = {
            let block = &mut self.cache[slot];
            block.valid = false;
            block.data.resize(want, 0);
            self.device.read_at(block_start, &mut block.data)?
        };
        self.counters.device_reads.fetch_add(1, Ordering::Relaxed);
        self.counters.device_bytes.fetch_add(got as u64, Ordering::Relaxed);

        let block = &mut self.cache[slot];
        block.data.truncate(got);
        block.start = block_start;
        block.valid = got > 0;

        if got == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "device returned no data"));
        }
        Ok(slot)
    }
}

impl<D: BlockDevice> Read for BlockReader<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.length - self.position) as usize;

        let mut written = 0;
        while written < want {
            let pos = self.position + written as u64;
            let block_start = pos / BLOCK_SIZE * BLOCK_SIZE;
            let slot = self.load(block_start)?;

            let offset_in_block = (pos - block_start) as usize;
            let block = &self.cache[slot];
            if offset_in_block >= block.data.len() {
                break;
            }
            let n = (block.data.len() - offset_in_block).min(want - written);
            buf[written..written + n]
                .copy_from_slice(&block.data[offset_in_block..offset_in_block + n]);
            written += n;
        }

        self.position += written as u64;
        Ok(written)
    }
}

impl<D: BlockDevice> Seek for BlockReader<D> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.length as i128 + n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start of volume"));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StrictDevice {
        data: Vec<u8>,
        reads: usize,
    }

    impl StrictDevice {
        fn new(len: usize) -> Self {
            StrictDevice { data: (0..len).map(|i| (i % 251) as u8).collect(), reads: 0 }
        }
    }

    impl BlockDevice for StrictDevice {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            assert_eq!(offset % BLOCK_SIZE, 0, "unaligned read offset {offset}");
            assert_eq!(buf.len() as u64 % 512, 0, "unaligned read length {}", buf.len());
            self.reads += 1;
            let start = offset as usize;
            let n = buf.len().min(self.data.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }

        fn length(&self) -> u64 {
            self.data.len() as u64
        }
    }

    fn reader(len: usize) -> BlockReader<StrictDevice> {
        BlockReader::new(StrictDevice::new(len))
    }

    #[test]
    fn unaligned_reads_are_served_from_aligned_device_reads() {
        let mut r = reader(1024 * 1024);
        r.seek(SeekFrom::Start(1337)).unwrap();
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], (1337 % 251) as u8);
    }

    #[test]
    fn reads_spanning_block_boundaries_are_contiguous() {
        let mut r = reader(1024 * 1024);
        let start = BLOCK_SIZE - 100;
        r.seek(SeekFrom::Start(start)).unwrap();
        let mut buf = vec![0u8; 200];
        r.read_exact(&mut buf).unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, ((start as usize + i) % 251) as u8, "byte {i}");
        }
    }

    #[test]
    fn reads_larger_than_the_whole_cache_work() {
        let size = BLOCK_SIZE as usize * BLOCK_COUNT * 3;
        let mut r = reader(size);
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf).unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, (i % 251) as u8, "byte {i}");
        }
    }

    #[test]
    fn repeated_reads_hit_the_cache() {
        let mut r = reader(1024 * 1024);
        let mut buf = [0u8; 64];
        r.seek(SeekFrom::Start(4096)).unwrap();
        r.read_exact(&mut buf).unwrap();
        let after_first = r.device.reads;

        for _ in 0..50 {
            r.seek(SeekFrom::Start(4096)).unwrap();
            r.read_exact(&mut buf).unwrap();
        }
        assert_eq!(r.device.reads, after_first, "cache did not absorb repeated reads");
    }

    #[test]
    fn alternating_distant_reads_stay_correct() {
        let mut r = reader(BLOCK_SIZE as usize * 64);
        let far = BLOCK_SIZE * 32;
        for _ in 0..10 {
            let mut a = [0u8; 8];
            r.seek(SeekFrom::Start(0)).unwrap();
            r.read_exact(&mut a).unwrap();
            assert_eq!(a[0], 0);

            let mut b = [0u8; 8];
            r.seek(SeekFrom::Start(far)).unwrap();
            r.read_exact(&mut b).unwrap();
            assert_eq!(b[0], ((far as usize) % 251) as u8);
        }
    }

    #[test]
    fn trailing_partial_block_is_readable() {
        let size = BLOCK_SIZE as usize + 512;
        let mut r = reader(size);
        r.seek(SeekFrom::Start(BLOCK_SIZE)).unwrap();
        let mut buf = vec![0u8; 512];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], ((BLOCK_SIZE as usize) % 251) as u8);
    }

    #[test]
    fn reads_at_and_past_the_end_return_zero_not_errors() {
        let mut r = reader(BLOCK_SIZE as usize);
        r.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(r.read(&mut [0u8; 16]).unwrap(), 0);
        r.seek(SeekFrom::Start(u64::MAX / 2)).unwrap();
        assert_eq!(r.read(&mut [0u8; 16]).unwrap(), 0);
    }

    #[test]
    fn read_is_truncated_at_the_end_of_the_volume() {
        let size = BLOCK_SIZE as usize;
        let mut r = reader(size);
        r.seek(SeekFrom::Start(size as u64 - 10)).unwrap();
        let mut buf = [0u8; 100];
        assert_eq!(r.read(&mut buf).unwrap(), 10);
    }

    #[test]
    fn seeking_before_the_start_is_rejected() {
        let mut r = reader(BLOCK_SIZE as usize);
        assert!(r.seek(SeekFrom::Current(-1)).is_err());
        assert!(r.seek(SeekFrom::End(-(BLOCK_SIZE as i64) - 1)).is_err());
        assert_eq!(r.stream_position().unwrap(), 0);
    }

    #[test]
    fn counters_match_what_the_device_was_asked_for() {
        let mut r = reader(BLOCK_SIZE as usize * 4);
        let counters = r.counters();
        let mut buf = [0u8; 64];

        r.seek(SeekFrom::Start(0)).unwrap();
        r.read_exact(&mut buf).unwrap();
        let after_first = counters.snapshot();
        assert_eq!(after_first.misses, 1);
        assert_eq!(after_first.hits, 0);
        assert_eq!(after_first.device_reads, 1);
        assert_eq!(after_first.device_bytes, BLOCK_SIZE);
        assert_eq!(after_first.conflicts, 0);

        for _ in 0..9 {
            r.seek(SeekFrom::Start(0)).unwrap();
            r.read_exact(&mut buf).unwrap();
        }
        let warm = counters.snapshot();
        assert_eq!(warm.hits, 9);
        assert_eq!(warm.device_reads, 1, "a hit must not reach the device");
        assert_eq!(warm.device_reads, r.device.reads as u64);
        assert_eq!(warm.since(after_first).hits, 9);
        assert!((warm.hit_rate().unwrap() - 0.9).abs() < 1e-12);
    }

    #[test]
    fn conflict_evictions_are_counted_separately_from_cold_misses() {
        let mut r = BlockReader::with_block_count(StrictDevice::new(BLOCK_SIZE as usize * 4), 1);
        let counters = r.counters();
        let mut buf = [0u8; 8];
        for _ in 0..5 {
            for start in [0, BLOCK_SIZE] {
                r.seek(SeekFrom::Start(start)).unwrap();
                r.read_exact(&mut buf).unwrap();
            }
        }
        let stats = counters.snapshot();
        assert_eq!(stats.hits, 0, "every access should collide");
        assert_eq!(stats.misses, 10);
        assert_eq!(stats.conflicts, 9);

        let mut roomy =
            BlockReader::with_block_count(StrictDevice::new(BLOCK_SIZE as usize * 4), 2);
        let roomy_counters = roomy.counters();
        for _ in 0..5 {
            for start in [0, BLOCK_SIZE] {
                roomy.seek(SeekFrom::Start(start)).unwrap();
                roomy.read_exact(&mut buf).unwrap();
            }
        }
        let roomy_stats = roomy_counters.snapshot();
        assert_eq!(roomy_stats.misses, 2);
        assert_eq!(roomy_stats.conflicts, 0);
        assert_eq!(roomy_stats.hits, 8);
    }

    #[test]
    fn a_failed_device_read_invalidates_the_slot_it_was_filling() {
        struct FailsAfterFirst {
            reads: usize,
        }
        impl BlockDevice for FailsAfterFirst {
            fn read_at(&mut self, _offset: u64, buf: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads == 1 {
                    buf.fill(0xAA);
                    return Ok(buf.len());
                }
                buf.fill(0xFF);
                Err(io::Error::other("the disk gave up"))
            }
            fn length(&self) -> u64 {
                BLOCK_SIZE * 4
            }
        }

        let mut r = BlockReader::with_block_count(FailsAfterFirst { reads: 0 }, 1);
        let mut buf = [0u8; 4];
        r.seek(SeekFrom::Start(0)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xAA; 4]);

        r.seek(SeekFrom::Start(BLOCK_SIZE)).unwrap();
        assert!(r.read(&mut buf).is_err());

        r.seek(SeekFrom::Start(0)).unwrap();
        assert!(
            r.read(&mut buf).is_err(),
            "the cache served bytes from a slot a failed read had scribbled on"
        );
    }

    #[test]
    fn an_unusual_cache_size_serves_the_same_bytes() {
        for blocks in [1usize, 3, 64] {
            let size = BLOCK_SIZE as usize * 8;
            let mut r = BlockReader::with_block_count(StrictDevice::new(size), blocks);
            let mut buf = vec![0u8; size];
            r.read_exact(&mut buf).unwrap();
            for (i, b) in buf.iter().enumerate() {
                assert_eq!(*b, (i % 251) as u8, "{blocks} blocks, byte {i}");
            }
        }
        let mut degenerate =
            BlockReader::with_block_count(StrictDevice::new(BLOCK_SIZE as usize), 0);
        let mut buf = [0u8; 4];
        degenerate.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn seek_variants_agree() {
        let mut r = reader(BLOCK_SIZE as usize * 4);
        assert_eq!(r.seek(SeekFrom::Start(100)).unwrap(), 100);
        assert_eq!(r.seek(SeekFrom::Current(50)).unwrap(), 150);
        assert_eq!(r.seek(SeekFrom::Current(-50)).unwrap(), 100);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), BLOCK_SIZE * 4);
    }
}

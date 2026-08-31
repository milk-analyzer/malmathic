pub const CHUNK_SIZE: usize = 32768;

pub const E8_FILESIZE: i32 = 12_000_000;

const E8_TAIL: usize = 10;

const NUM_POSITION_SLOTS: usize = 30;
const NUM_MAIN_SYMBOLS: usize = 256 + NUM_POSITION_SLOTS * 8;
const NUM_LENGTH_SYMBOLS: usize = 249;
const NUM_ALIGNED_SYMBOLS: usize = 8;
const NUM_PRETREE_SYMBOLS: usize = 20;
const MAX_CODE_BITS: usize = 16;
const NUM_PRIMARY_LENGTHS: usize = 7;
const MIN_MATCH: usize = 2;

const MAX_TRAILING_BITS: usize = 16;

const EXTRA_BITS: [u8; NUM_POSITION_SLOTS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const BASE: [u32; NUM_POSITION_SLOTS] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge(usize),
    Truncated,
    BadBlockType(u8),
    EmptyBlock,
    BlockOverrun { at: usize, block: usize, target: usize },
    OverSubscribed,
    BadCode(&'static str),
    BadOffset { offset: usize, produced: usize },
    MatchOverrun { produced: usize, length: usize, target: usize },
    ShortOutput { got: usize, want: usize },
    Trailing { bits: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLarge(n) => {
                write!(f, "an LZX chunk cannot hold {n} bytes; the limit is {CHUNK_SIZE}")
            }
            Error::Truncated => write!(f, "the LZX stream ended in the middle of a symbol"),
            Error::BadBlockType(t) => write!(f, "LZX block type {t} is not a block type"),
            Error::EmptyBlock => write!(f, "an LZX block declares zero bytes"),
            Error::BlockOverrun { at, block, target } => write!(
                f,
                "an LZX block of {block} bytes starting at {at} would overrun the {target}-byte \
                 chunk"
            ),
            Error::OverSubscribed => write!(f, "an LZX code-length table is not a prefix code"),
            Error::BadCode(tree) => write!(f, "an LZX {tree} code matches no symbol"),
            Error::BadOffset { offset, produced } => write!(
                f,
                "an LZX match at offset {offset} reaches before the start of a chunk holding \
                 {produced} bytes"
            ),
            Error::MatchOverrun { produced, length, target } => write!(
                f,
                "an LZX match of {length} bytes at {produced} runs past the {target}-byte chunk"
            ),
            Error::ShortOutput { got, want } => {
                write!(f, "an LZX chunk decoded to {got} bytes where the table says {want}")
            }
            Error::Trailing { bits } => write!(
                f,
                "{bits} bits are left after the last LZX block, more than the encoder's padding \
                 explains"
            ),
        }
    }
}

impl std::error::Error for Error {}

struct Bits<'a> {
    data: &'a [u8],
    fed: usize,
    buf: u32,
    nbuf: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits { data, fed: 0, buf: 0, nbuf: 0 }
    }

    #[inline]
    fn consumed_bits(&self) -> usize {
        self.fed * 8 - self.nbuf
    }

    #[inline]
    fn fill(&mut self) {
        while self.nbuf <= 16 {
            let lo = u32::from(self.data.get(self.fed).copied().unwrap_or(0));
            let hi = u32::from(self.data.get(self.fed + 1).copied().unwrap_or(0));
            self.buf = (self.buf << 16) | (lo | (hi << 8));
            self.nbuf += 16;
            self.fed += 2;
        }
    }

    #[inline]
    fn peek16(&mut self) -> u32 {
        self.fill();
        (self.buf >> (self.nbuf - 16)) & 0xffff
    }

    #[inline]
    fn skip(&mut self, n: usize) -> Result<(), Error> {
        debug_assert!(n <= 16);
        self.fill();
        self.nbuf -= n;
        if self.consumed_bits() > self.data.len() * 8 {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        debug_assert!(n <= 16);
        self.fill();
        let v = (self.buf >> (self.nbuf - n)) & ((1u32 << n) - 1);
        self.nbuf -= n;
        if self.consumed_bits() > self.data.len() * 8 {
            return Err(Error::Truncated);
        }
        Ok(v)
    }

    fn align16(&mut self) -> Result<(), Error> {
        let c = self.consumed_bits();
        let pad = (16 - (c % 16)) % 16;
        if pad != 0 {
            self.take(pad)?;
        }
        let at = self.consumed_bits() / 8;
        self.fed = at;
        self.buf = 0;
        self.nbuf = 0;
        Ok(())
    }

    fn byte_pos(&self) -> usize {
        debug_assert_eq!(self.nbuf, 0);
        self.fed
    }

    fn seek_bytes(&mut self, at: usize) -> Result<(), Error> {
        if at > self.data.len() {
            return Err(Error::Truncated);
        }
        self.fed = at;
        self.buf = 0;
        self.nbuf = 0;
        Ok(())
    }
}

struct Tree {
    counts: [u16; MAX_CODE_BITS + 1],
    first: [u32; MAX_CODE_BITS + 1],
    offset: [u16; MAX_CODE_BITS + 1],
    syms: Vec<u16>,
    max_len: usize,
    name: &'static str,
}

impl Tree {
    fn new(name: &'static str, capacity: usize) -> Self {
        Tree {
            counts: [0; MAX_CODE_BITS + 1],
            first: [0; MAX_CODE_BITS + 1],
            offset: [0; MAX_CODE_BITS + 1],
            syms: Vec::with_capacity(capacity),
            max_len: 0,
            name,
        }
    }

    fn build(&mut self, lens: &[u8]) -> Result<(), Error> {
        self.counts = [0; MAX_CODE_BITS + 1];
        self.max_len = 0;
        for &l in lens {
            let l = l as usize;
            if l > MAX_CODE_BITS {
                return Err(Error::OverSubscribed);
            }
            if l != 0 {
                self.counts[l] += 1;
                if l > self.max_len {
                    self.max_len = l;
                }
            }
        }
        let mut left: i64 = 1;
        for l in 1..=self.max_len {
            left <<= 1;
            left -= i64::from(self.counts[l]);
            if left < 0 {
                return Err(Error::OverSubscribed);
            }
        }

        let mut running = 0u16;
        for l in 1..=self.max_len {
            self.offset[l] = running;
            running += self.counts[l];
        }
        self.syms.clear();
        self.syms.resize(running as usize, 0);
        let mut next = self.offset;
        for (sym, &l) in lens.iter().enumerate() {
            let l = l as usize;
            if l != 0 {
                self.syms[next[l] as usize] = sym as u16;
                next[l] += 1;
            }
        }

        let mut code = 0u32;
        for l in 1..=self.max_len {
            code = (code + u32::from(if l >= 2 { self.counts[l - 1] } else { 0 })) << 1;
            self.first[l] = code;
        }
        Ok(())
    }

    #[inline]
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, Error> {
        let window = bits.peek16();
        for l in 1..=self.max_len {
            let c = u32::from(self.counts[l]);
            if c == 0 {
                continue;
            }
            let code = window >> (16 - l);
            if code >= self.first[l] && code - self.first[l] < c {
                bits.skip(l)?;
                return Ok(self.syms[self.offset[l] as usize + (code - self.first[l]) as usize]);
            }
        }
        Err(Error::BadCode(self.name))
    }
}

pub struct Decoder {
    main_lens: Vec<u8>,
    length_lens: Vec<u8>,
    aligned_lens: [u8; NUM_ALIGNED_SYMBOLS],
    pretree_lens: [u8; NUM_PRETREE_SYMBOLS],
    main: Tree,
    length: Tree,
    aligned: Tree,
    pretree: Tree,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    #[must_use]
    pub fn new() -> Self {
        Decoder {
            main_lens: vec![0; NUM_MAIN_SYMBOLS],
            length_lens: vec![0; NUM_LENGTH_SYMBOLS],
            aligned_lens: [0; NUM_ALIGNED_SYMBOLS],
            pretree_lens: [0; NUM_PRETREE_SYMBOLS],
            main: Tree::new("main tree", NUM_MAIN_SYMBOLS),
            length: Tree::new("length tree", NUM_LENGTH_SYMBOLS),
            aligned: Tree::new("aligned-offset tree", NUM_ALIGNED_SYMBOLS),
            pretree: Tree::new("pre-tree", NUM_PRETREE_SYMBOLS),
        }
    }

    pub fn decompress_into(
        &mut self,
        input: &[u8],
        target: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let start = out.len();
        match self.run(input, target, out) {
            Ok(()) => Ok(()),
            Err(e) => {
                out.truncate(start);
                Err(e)
            }
        }
    }

    fn run(&mut self, input: &[u8], target: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        if target > CHUNK_SIZE {
            return Err(Error::TooLarge(target));
        }
        if target == 0 {
            return Ok(());
        }
        let start = out.len();
        out.reserve(target);

        let mut bits = Bits::new(input);
        self.main_lens.iter_mut().for_each(|l| *l = 0);
        self.length_lens.iter_mut().for_each(|l| *l = 0);
        let mut r: [u32; 3] = [1, 1, 1];

        while out.len() - start < target {
            let block_type = bits.take(3)? as u8;
            let block_size = if bits.take(1)? == 1 { CHUNK_SIZE } else { bits.take(16)? as usize };
            if block_size == 0 {
                return Err(Error::EmptyBlock);
            }
            let produced = out.len() - start;
            if produced + block_size > target {
                return Err(Error::BlockOverrun { at: produced, block: block_size, target });
            }

            match block_type {
                3 => {
                    bits.align16()?;
                    let at = bits.byte_pos();
                    let after_queue = at.checked_add(12).ok_or(Error::Truncated)?;
                    if after_queue > input.len() {
                        return Err(Error::Truncated);
                    }
                    for (i, slot) in r.iter_mut().enumerate() {
                        let b = &input[at + i * 4..at + i * 4 + 4];
                        *slot = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                        if *slot == 0 {
                            return Err(Error::BadOffset { offset: 0, produced });
                        }
                    }
                    let data_end = after_queue.checked_add(block_size).ok_or(Error::Truncated)?;
                    if data_end > input.len() {
                        return Err(Error::Truncated);
                    }
                    out.extend_from_slice(&input[after_queue..data_end]);
                    let resume = if block_size % 2 == 1 { data_end + 1 } else { data_end };
                    bits.seek_bytes(resume.min(input.len()))?;
                    continue;
                }
                1 | 2 => {}
                other => return Err(Error::BadBlockType(other)),
            }

            let aligned_block = block_type == 2;
            if aligned_block {
                for slot in self.aligned_lens.iter_mut() {
                    *slot = bits.take(3)? as u8;
                }
                self.aligned.build(&self.aligned_lens)?;
            }
            read_lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.pretree_lens,
                &mut self.main_lens,
                0,
                256,
            )?;
            read_lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.pretree_lens,
                &mut self.main_lens,
                256,
                NUM_MAIN_SYMBOLS,
            )?;
            self.main.build(&self.main_lens)?;
            read_lengths(
                &mut bits,
                &mut self.pretree,
                &mut self.pretree_lens,
                &mut self.length_lens,
                0,
                NUM_LENGTH_SYMBOLS,
            )?;
            self.length.build(&self.length_lens)?;

            let block_end = out.len() + block_size;
            while out.len() < block_end {
                let sym = self.main.decode(&mut bits)? as usize;
                if sym < 256 {
                    out.push(sym as u8);
                    continue;
                }
                let sym = sym - 256;
                let length_header = sym & NUM_PRIMARY_LENGTHS;
                let slot = sym >> 3;
                if slot >= NUM_POSITION_SLOTS {
                    return Err(Error::BadCode("main tree"));
                }
                let match_len = if length_header == NUM_PRIMARY_LENGTHS {
                    self.length.decode(&mut bits)? as usize + NUM_PRIMARY_LENGTHS + MIN_MATCH
                } else {
                    length_header + MIN_MATCH
                };

                let offset = if slot < 3 {
                    let o = r[slot];
                    if slot != 0 {
                        r[slot] = r[0];
                        r[0] = o;
                    }
                    o
                } else {
                    let extra = EXTRA_BITS[slot] as usize;
                    let formatted = if aligned_block && extra >= 3 {
                        let verbatim = bits.take(extra - 3)?;
                        let aligned = u32::from(self.aligned.decode(&mut bits)?);
                        BASE[slot] + (verbatim << 3) + aligned
                    } else {
                        BASE[slot] + bits.take(extra)?
                    };
                    let o = formatted.wrapping_sub(2);
                    r[2] = r[1];
                    r[1] = r[0];
                    r[0] = o;
                    o
                };

                let produced = out.len() - start;
                let offset = offset as usize;
                if offset == 0 || offset > produced {
                    return Err(Error::BadOffset { offset, produced });
                }
                if produced + match_len > target {
                    return Err(Error::MatchOverrun { produced, length: match_len, target });
                }
                for from in (out.len() - offset..).take(match_len) {
                    let b = out[from];
                    out.push(b);
                }
            }
            if out.len() != block_end {
                return Err(Error::BlockOverrun {
                    at: block_end - start - block_size,
                    block: block_size,
                    target,
                });
            }
        }

        let got = out.len() - start;
        if got != target {
            return Err(Error::ShortOutput { got, want: target });
        }

        let total = input.len() * 8;
        let left = total.saturating_sub(bits.consumed_bits());
        if left >= MAX_TRAILING_BITS {
            return Err(Error::Trailing { bits: left });
        }

        undo_e8(&mut out[start..]);
        Ok(())
    }
}

fn read_lengths(
    bits: &mut Bits<'_>,
    pretree: &mut Tree,
    pretree_lens: &mut [u8; NUM_PRETREE_SYMBOLS],
    lens: &mut [u8],
    from: usize,
    to: usize,
) -> Result<(), Error> {
    for slot in pretree_lens.iter_mut() {
        *slot = bits.take(4)? as u8;
    }
    pretree.build(pretree_lens)?;

    let mut i = from;
    while i < to {
        let sym = pretree.decode(bits)?;
        match sym {
            17 => {
                let n = bits.take(4)? as usize + 4;
                for _ in 0..n {
                    if i >= to {
                        break;
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let n = bits.take(5)? as usize + 20;
                for _ in 0..n {
                    if i >= to {
                        break;
                    }
                    lens[i] = 0;
                    i += 1;
                }
            }
            19 => {
                let n = bits.take(1)? as usize + 4;
                let next = pretree.decode(bits)?;
                if next > 16 {
                    return Err(Error::BadCode("pre-tree"));
                }
                let value = ((17 + i32::from(lens[i]) - i32::from(next)) % 17) as u8;
                for _ in 0..n {
                    if i >= to {
                        break;
                    }
                    lens[i] = value;
                    i += 1;
                }
            }
            s if s <= 16 => {
                lens[i] = ((17 + i32::from(lens[i]) - i32::from(s)) % 17) as u8;
                i += 1;
            }
            _ => return Err(Error::BadCode("pre-tree")),
        }
    }
    Ok(())
}

fn undo_e8(chunk: &mut [u8]) {
    let n = chunk.len();
    if n <= E8_TAIL {
        return;
    }
    let end = n - E8_TAIL;
    let mut i = 0usize;
    while i < end {
        if chunk[i] != 0xE8 {
            i += 1;
            continue;
        }
        let at = i + 1;
        let absolute = i32::from_le_bytes([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]]);
        let pos = i as i32;
        let relative = if absolute >= 0 {
            if absolute < E8_FILESIZE {
                Some(absolute.wrapping_sub(pos))
            } else {
                None
            }
        } else if absolute >= -pos {
            Some(absolute.wrapping_add(E8_FILESIZE))
        } else {
            None
        };
        if let Some(v) = relative {
            chunk[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        i += 5;
    }
}

pub fn decompress(input: &[u8], target: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    Decoder::new().decompress_into(input, target, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(stream: &[u8], plaintext_len: usize) -> Option<Vec<(&[u8], usize)>> {
        let n = plaintext_len.div_ceil(CHUNK_SIZE);
        let table_bytes = (n - 1) * 4;
        if stream.len() < table_bytes {
            return None;
        }
        let (table, body) = stream.split_at(table_bytes);
        let at = |i: usize| -> usize {
            if i == 0 {
                0
            } else {
                u32::from_le_bytes(table[(i - 1) * 4..(i - 1) * 4 + 4].try_into().unwrap()) as usize
            }
        };
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let start = at(i);
            let end = if i + 1 == n { body.len() } else { at(i + 1) };
            if end < start || end > body.len() {
                return None;
            }
            let plain = if i + 1 == n { plaintext_len - i * CHUNK_SIZE } else { CHUNK_SIZE };
            out.push((&body[start..end], plain));
        }
        Some(out)
    }

    fn decode_stream(stream: &[u8], plaintext_len: usize) -> Result<Vec<u8>, Error> {
        let mut decoder = Decoder::new();
        let mut out = Vec::with_capacity(plaintext_len);
        let Some(pieces) = chunks(stream, plaintext_len) else { return Err(Error::Truncated) };
        for (piece, plain) in pieces {
            if piece.len() == plain {
                out.extend_from_slice(piece);
            } else {
                decoder.decompress_into(piece, plain, &mut out)?;
            }
        }
        Ok(out)
    }

    const DRTM_BOOT_METADATA: &[u8] = include_bytes!("../fixtures/lzx/drtm-bootmetadata.lzxstream");
    const DRTM_BOOT_METADATA_LEN: usize = 8008;
    const DRTM_BOOT_METADATA_SHA1: &str = "7c7c9878bc9a42c50fb2f18ccbe091367b9917ba";

    const PSEUDOCODE: &[u8] = include_bytes!("../fixtures/lzx/pseudocode.lzxstream");
    const RUNS: &[u8] = include_bytes!("../fixtures/lzx/runs.lzxstream");
    const BOUNDARY_A: &[u8] = include_bytes!("../fixtures/lzx/boundary_a.lzxstream");
    const BOUNDARY_B: &[u8] = include_bytes!("../fixtures/lzx/boundary_b.lzxstream");

    struct Lcg(u32);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (self.0 >> 8) & 0x00ff_ffff
        }
    }

    fn pseudocode(n: usize) -> Vec<u8> {
        let mut g = Lcg(0x1234_5678);
        let mut pool: Vec<[u8; 8]> = Vec::with_capacity(64);
        for _ in 0..64 {
            let mut item = [0u8; 8];
            for (k, slot) in item.iter_mut().take(3).enumerate() {
                *slot = ((g.next() >> (8 * k)) & 0xff) as u8;
            }
            item[3..8].copy_from_slice(&[0x48, 0x8b, 0xc1, 0x33, 0xd2]);
            pool.push(item);
        }
        let targets = [0x1000i32, 0x2400, 0x8800, 0x1f000, 0x3b000];
        let mut b: Vec<u8> = Vec::with_capacity(n + 16);
        while b.len() < n {
            let v = g.next();
            if v.is_multiple_of(7) {
                let pos = (b.len() % CHUNK_SIZE) as i32;
                let t = targets[((v >> 4) as usize) % targets.len()];
                b.push(0xE8);
                b.extend_from_slice(&(t - pos).to_le_bytes());
            } else {
                b.extend_from_slice(&pool[(v as usize) % 64]);
            }
        }
        b.truncate(n);
        b
    }

    fn runs(n: usize) -> Vec<u8> {
        let mut g = Lcg(0xDEAD_BEEF);
        let mut b: Vec<u8> = Vec::with_capacity(n + 512);
        while b.len() < n {
            let v = g.next();
            if v.is_multiple_of(3) {
                let count = ((v >> 8) % 300) as usize + 1;
                let byte = (v & 0xff) as u8;
                for _ in 0..count {
                    b.push(byte);
                }
            } else {
                for k in 0..3 {
                    b.push(((g.next() >> (8 * k)) & 0xff) as u8);
                }
            }
        }
        b.truncate(n);
        b
    }

    fn boundary(filesize: i32, n: usize) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::with_capacity(n + 16);
        while b.len() < n {
            let p = (b.len() % CHUNK_SIZE) as i32;
            b.push(0xE8);
            b.extend_from_slice(&(filesize - p).to_le_bytes());
            b.extend_from_slice(&[
                0x90, 0x48, 0x8b, 0xc1, 0x33, 0xd2, 0x41, 0xb8, 0x10, 0x00, 0x00,
            ]);
        }
        b.truncate(n);
        b
    }

    fn sha1_hex(bytes: &[u8]) -> String {
        crate::FileHash::compute(bytes).sha1_hex().unwrap_or_default()
    }

    #[test]
    fn a_microsoft_wim_resource_decodes_to_the_hash_microsoft_recorded_for_it() {
        let out = decode_stream(DRTM_BOOT_METADATA, DRTM_BOOT_METADATA_LEN).expect("decodes");
        assert_eq!(out.len(), DRTM_BOOT_METADATA_LEN);
        assert_eq!(sha1_hex(&out), DRTM_BOOT_METADATA_SHA1);
    }

    #[test]
    fn a_multi_chunk_resource_with_a_partial_last_chunk_decodes_byte_for_byte() {
        let want = pseudocode(140_000);
        let got = decode_stream(PSEUDOCODE, want.len()).expect("decodes");
        assert_eq!(got.len(), want.len());
        assert!(got == want, "decoded bytes differ from the plaintext wimgapi was given");
    }

    #[test]
    fn long_matches_and_literals_decode_byte_for_byte() {
        let want = runs(80_000);
        let got = decode_stream(RUNS, want.len()).expect("decodes");
        assert!(got == want);
    }

    #[test]
    fn the_x86_translation_magic_file_size_is_twelve_million() {
        assert_eq!(E8_FILESIZE, 12_000_000);
        for (stream, filesize) in [(BOUNDARY_A, 12_000_000i32), (BOUNDARY_B, 11_999_999)] {
            let want = boundary(filesize, 65_536);
            let got = decode_stream(stream, want.len()).expect("decodes");
            assert!(got == want, "boundary probe for {filesize} did not round-trip");
        }
    }

    #[test]
    fn the_two_boundary_probes_disagree() {
        assert_ne!(boundary(12_000_000, 65_536), boundary(11_999_999, 65_536));
    }

    #[test]
    fn a_chunk_holding_more_than_a_window_is_refused_rather_than_allocated() {
        let mut out = Vec::new();
        assert_eq!(
            Decoder::new().decompress_into(&[0u8; 8], CHUNK_SIZE + 1, &mut out),
            Err(Error::TooLarge(CHUNK_SIZE + 1))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_corrupted_stream_never_yields_the_plaintext_and_never_yields_a_prefix() {
        let want = pseudocode(140_000);
        let pieces = chunks(PSEUDOCODE, want.len()).expect("the fixture describes itself");
        let table_bytes = (pieces.len() - 1) * 4;
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut at = table_bytes;
        for (piece, _) in &pieces {
            spans.push((at, at + piece.len().saturating_sub(2)));
            at += piece.len();
        }

        let mut errors = 0usize;
        let mut wrong = 0usize;
        let mut probed = 0usize;
        for (from, to) in spans {
            for byte in (from..to).step_by(211) {
                for bit in 0..8 {
                    probed += 1;
                    let mut damaged = PSEUDOCODE.to_vec();
                    damaged[byte] ^= 1 << bit;
                    match decode_stream(&damaged, want.len()) {
                        Err(_) => errors += 1,
                        Ok(got) => {
                            assert_eq!(
                                got.len(),
                                want.len(),
                                "a short decode was presented as a whole"
                            );
                            if got != want {
                                wrong += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(probed > 500, "the probe did not cover the fixture");
        assert!(errors > 0, "no single-bit change was even noticed");
        assert_eq!(
            errors + wrong,
            probed,
            "a damaged stream decoded to the original plaintext, which cannot happen"
        );
    }

    #[test]
    fn a_truncated_stream_is_refused_rather_than_completed() {
        for cut in [1usize, 7, 64, 500, 2000, 5000] {
            if cut >= RUNS.len() {
                continue;
            }
            let short = &RUNS[..RUNS.len() - cut];
            let r = decode_stream(short, 80_000);
            assert!(r.is_err(), "a stream {cut} bytes short still produced a file");
        }
    }

    #[test]
    fn the_stream_does_not_begin_with_a_cab_style_translation_flag() {
        let (_, body) = RUNS.split_at(8);
        let first = &body[..2036];
        let mut shifted = Vec::with_capacity(first.len() + 1);
        let mut carry = 0u8;
        for &b in first {
            shifted.push((b >> 1) | carry);
            carry = (b & 1) << 7;
        }
        shifted.push(carry);
        let mut out = Vec::new();
        assert!(
            Decoder::new().decompress_into(&shifted, CHUNK_SIZE, &mut out).is_err(),
            "a stream read one bit off decoded anyway, so the framing is not pinned"
        );
    }

    #[test]
    fn every_error_says_what_went_wrong_without_claiming_bytes() {
        let cases = [
            Error::TooLarge(99_999),
            Error::Truncated,
            Error::BadBlockType(0),
            Error::EmptyBlock,
            Error::BlockOverrun { at: 3, block: 4, target: 5 },
            Error::OverSubscribed,
            Error::BadCode("main tree"),
            Error::BadOffset { offset: 9, produced: 2 },
            Error::MatchOverrun { produced: 1, length: 2, target: 3 },
            Error::ShortOutput { got: 1, want: 2 },
            Error::Trailing { bits: 40 },
        ];
        for c in cases {
            let text = c.to_string();
            assert!(text.contains("LZX") || text.contains("stream"), "{text}");
        }
    }
}

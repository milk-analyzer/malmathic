pub const MAX_OUTPUT: usize = 64 * 1024 * 1024;
const BLOCK_SIZE: usize = 65536;
const TABLE_BYTES: usize = 256;
const MAX_CODE_BITS: u32 = 15;
const LOOKUP_ENTRIES: usize = 1 << MAX_CODE_BITS;
const NO_SYMBOL: u16 = 0xffff;

pub fn decompress_mam(bytes: &[u8]) -> Option<Vec<u8>> {
    let signature = read_u32(bytes, 0)?;
    if signature & 0x00ff_ffff != 0x004d_414d {
        return None;
    }
    if (signature >> 24) & 0x0f != 4 {
        return None;
    }
    let payload_at = if (signature >> 28) & 0x0f != 0 { 12 } else { 8 };

    let uncompressed_size = read_u32(bytes, 4)? as usize;
    if uncompressed_size == 0 {
        return None;
    }
    let payload = bytes.get(payload_at..)?;
    Some(decompress(payload, uncompressed_size.min(MAX_OUTPUT)))
}

pub fn decompress(input: &[u8], target: usize) -> Vec<u8> {
    Decoder::new().decompress(input, target)
}

pub struct Decoder {
    lookup: Vec<u16>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { lookup: vec![NO_SYMBOL; LOOKUP_ENTRIES] }
    }

    pub fn decompress(&mut self, input: &[u8], target: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(target.min(BLOCK_SIZE));
        self.decompress_into(input, target, &mut out);
        out
    }

    pub fn decompress_into(&mut self, input: &[u8], target: usize, out: &mut Vec<u8>) {
        let base = out.len();
        decompress_inner(input, target, &mut self.lookup, out, base);
    }
}

fn decompress_inner(
    input: &[u8],
    target: usize,
    lookup: &mut [u16],
    out: &mut Vec<u8>,
    base: usize,
) {
    let target = match base.checked_add(target) {
        Some(t) => t,
        None => return,
    };
    let mut pos = 0usize;

    while out.len() < target {
        let table_end = match pos.checked_add(TABLE_BYTES) {
            Some(e) => e,
            None => break,
        };
        let Some(table) = input.get(pos..table_end) else { break };
        if !build_lookup(table, lookup) {
            break;
        }

        let mut reader = BitReader::new(input, table_end);
        let block_end = out.len().saturating_add(BLOCK_SIZE).min(target);
        let finished_cleanly = decode_block(&mut reader, lookup, out, block_end, target, base);

        if !finished_cleanly || reader.pos <= table_end || out.len() < block_end {
            break;
        }
        pos = reader.pos;
    }
}

fn decode_block(
    reader: &mut BitReader<'_>,
    lookup: &[u16],
    out: &mut Vec<u8>,
    block_end: usize,
    target: usize,
    base: usize,
) -> bool {
    while out.len() < block_end {
        let Some(symbol) = reader.symbol(lookup) else { return false };
        if symbol < 256 {
            out.push(symbol as u8);
            continue;
        }

        let encoded = symbol - 256;
        let offset_bits = (encoded >> 4) & 15;
        let mut length = (encoded & 15) as usize;

        let offset = (1usize << offset_bits) + reader.peek(offset_bits as u32) as usize;

        if length == 15 {
            let Some(extra) = reader.take_u8() else { return false };
            length += extra as usize;
            if length == 270 {
                let Some(wide) = reader.take_u16() else { return false };
                length = if wide == 0 {
                    match reader.take_u32() {
                        Some(v) => v as usize,
                        None => return false,
                    }
                } else {
                    wide as usize
                };
            }
        }
        length = length.saturating_add(3);
        reader.consume(offset_bits as u32);

        if offset > out.len() - base || out.len().saturating_add(length) > target {
            return false;
        }
        let start = out.len() - offset;
        for i in 0..length {
            let b = out[start + i];
            out.push(b);
        }
    }
    true
}

fn build_lookup(table: &[u8], lookup: &mut [u16]) -> bool {
    if table.len() < TABLE_BYTES || lookup.len() < LOOKUP_ENTRIES {
        return false;
    }
    let mut lengths = [0u8; 512];
    for (i, &byte) in table.iter().take(TABLE_BYTES).enumerate() {
        lengths[i * 2] = byte & 0x0f;
        lengths[i * 2 + 1] = byte >> 4;
    }

    lookup[..LOOKUP_ENTRIES].fill(NO_SYMBOL);
    let mut code: u32 = 0;
    for len in 1..=MAX_CODE_BITS {
        for (symbol, &sym_len) in lengths.iter().enumerate() {
            if u32::from(sym_len) != len {
                continue;
            }
            let shift = MAX_CODE_BITS - len;
            let start = match code.checked_shl(shift) {
                Some(s) => s as usize,
                None => return false,
            };
            let span = 1usize << shift;
            let end = match start.checked_add(span) {
                Some(e) => e,
                None => return false,
            };
            if end > LOOKUP_ENTRIES {
                return false;
            }
            let entry = (symbol as u16) | ((len as u16) << 9);
            lookup[start..end].fill(entry);
            code += 1;
        }
        code <<= 1;
    }
    true
}

struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    bits: u32,
    extra: i32,
    overrun: bool,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8], pos: usize) -> Self {
        let mut r = BitReader { input, pos, bits: 0, extra: 16, overrun: false };
        let high = r.next_u16();
        let low = r.next_u16();
        r.bits = (u32::from(high) << 16) | u32::from(low);
        r
    }

    fn symbol(&mut self, lookup: &[u16]) -> Option<u16> {
        if self.overrun {
            return None;
        }
        let entry = *lookup.get((self.bits >> (32 - MAX_CODE_BITS)) as usize)?;
        if entry == NO_SYMBOL {
            return None;
        }
        let len = u32::from(entry >> 9);
        if len == 0 || len > MAX_CODE_BITS {
            return None;
        }
        self.consume(len);
        Some(entry & 0x1ff)
    }

    fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.bits >> (32 - n)
        }
    }

    fn consume(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        self.bits = self.bits.wrapping_shl(n);
        self.extra -= n as i32;
        if self.extra < 0 {
            let word = self.next_u16();
            self.bits |= u32::from(word) << (-self.extra) as u32;
            self.extra += 16;
        }
    }

    fn next_u16(&mut self) -> u16 {
        let lo = self.next_u8();
        let hi = self.next_u8();
        (u16::from(hi) << 8) | u16::from(lo)
    }

    fn next_u8(&mut self) -> u8 {
        match self.input.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b
            }
            None => {
                self.overrun = true;
                0
            }
        }
    }

    fn take_u8(&mut self) -> Option<u8> {
        let b = *self.input.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let end = self.pos.checked_add(2)?;
        let s = self.input.get(self.pos..end)?;
        self.pos = end;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    fn take_u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let s = self.input.get(self.pos..end)?;
        self.pos = end;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s = bytes.get(at..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

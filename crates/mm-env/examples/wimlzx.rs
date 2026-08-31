use std::path::Path;

const HEADER: usize = 208;
const RESHDR: usize = 24;
const LOOKUP_ENTRY: usize = 50;

const FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
const FLAG_COMPRESS_LZX: u32 = 0x0004_0000;
const FLAG_COMPRESS_LZMS: u32 = 0x0008_0000;

const RES_COMPRESSED: u8 = 0x04;

struct ResHdr {
    size: u64,
    flags: u8,
    offset: u64,
    original: u64,
}

fn reshdr(b: &[u8], at: usize) -> Option<ResHdr> {
    let s = b.get(at..at + RESHDR)?;
    let mut size = 0u64;
    for (i, byte) in s[0..7].iter().enumerate() {
        size |= u64::from(*byte) << (8 * i);
    }
    Some(ResHdr {
        size,
        flags: s[7],
        offset: u64::from_le_bytes(s[8..16].try_into().ok()?),
        original: u64::from_le_bytes(s[16..24].try_into().ok()?),
    })
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: wimlzx <file.wim>");
        std::process::exit(2);
    };
    let data = match std::fs::read(Path::new(&path)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(2);
        }
    };
    if data.len() < HEADER || &data[0..8] != b"MSWIM\0\0\0" {
        eprintln!("{path} is not a WIM");
        std::process::exit(2);
    }

    let flags = u32le(&data, 16);
    let chunk_size = u32le(&data, 20) as usize;
    let algorithm = if flags & FLAG_COMPRESS_LZX != 0 {
        "LZX"
    } else if flags & FLAG_COMPRESS_XPRESS != 0 {
        "XPRESS"
    } else if flags & FLAG_COMPRESS_LZMS != 0 {
        "LZMS"
    } else {
        "none"
    };
    println!("{path}");
    println!("  header flags 0x{flags:08x}  compression {algorithm}  chunk size {chunk_size}");
    if algorithm != "LZX" {
        println!("  -- not an LZX WIM; nothing here decodes it. Export it to LZX first.");
        std::process::exit(1);
    }
    if chunk_size != mm_core::lzx::CHUNK_SIZE {
        println!(
            "  -- chunk size is not {}; this build decodes only that",
            mm_core::lzx::CHUNK_SIZE
        );
        std::process::exit(1);
    }

    let Some(lookup) = reshdr(&data, 48) else {
        eprintln!("  truncated header");
        std::process::exit(2);
    };
    let at = lookup.offset as usize;
    let Some(table) = data.get(at..at + lookup.size as usize) else {
        eprintln!("  lookup table runs past the file");
        std::process::exit(2);
    };

    let mut decoder = mm_core::lzx::Decoder::new();
    let (mut ok, mut bad, mut raw_chunks, mut lzx_chunks, mut partial) = (0, 0, 0, 0, 0);
    for entry in table.as_chunks::<LOOKUP_ENTRY>().0 {
        let Some(res) = reshdr(entry, 0) else { continue };
        let mut sha = [0u8; 20];
        sha.copy_from_slice(&entry[30..50]);
        if res.flags & RES_COMPRESSED == 0 {
            continue;
        }
        let original = res.original as usize;
        let chunks = original.div_ceil(chunk_size);
        let width = if res.original > u64::from(u32::MAX) { 8 } else { 4 };
        let base = res.offset as usize;
        let table_bytes = (chunks - 1) * width;
        let Some(ctable) = data.get(base..base + table_bytes) else {
            println!("  resource at {base}: chunk table runs past the file");
            bad += 1;
            continue;
        };
        let body_at = base + table_bytes;
        let body_len = res.size as usize - table_bytes;
        let offset_of = |i: usize| -> usize {
            if i == 0 {
                return 0;
            }
            let a = (i - 1) * width;
            if width == 8 {
                u64::from_le_bytes(ctable[a..a + 8].try_into().unwrap_or([0; 8])) as usize
            } else {
                u32le(ctable, a) as usize
            }
        };

        let mut out: Vec<u8> = Vec::with_capacity(original);
        let mut failed: Option<String> = None;
        for i in 0..chunks {
            let s = offset_of(i);
            let e = if i + 1 == chunks { body_len } else { offset_of(i + 1) };
            let plain = if i + 1 == chunks { original - i * chunk_size } else { chunk_size };
            if plain != chunk_size {
                partial += 1;
            }
            let Some(piece) = data.get(body_at + s..body_at + e) else {
                failed = Some(format!("chunk {i} runs past the file"));
                break;
            };
            if piece.len() == plain {
                raw_chunks += 1;
                out.extend_from_slice(piece);
                continue;
            }
            lzx_chunks += 1;
            if let Err(err) = decoder.decompress_into(piece, plain, &mut out) {
                failed = Some(format!("chunk {i} ({} bytes -> {plain}): {err}", piece.len()));
                break;
            }
        }
        let name = format!("{} bytes at {}", res.original, res.offset);
        match failed {
            Some(why) => {
                println!("  FAIL {name}: {why}");
                bad += 1;
            }
            None => {
                let got = mm_core::FileHash::compute(&out).sha1.unwrap_or([0; 20]);
                if got == sha {
                    ok += 1;
                } else {
                    println!("  FAIL {name}: sha1 {} but the WIM records {}", hex(&got), hex(&sha));
                    bad += 1;
                }
            }
        }
    }

    println!(
        "  {ok} resources reproduce the SHA-1 the WIM records, {bad} do not\n  \
         {lzx_chunks} LZX chunks decoded, {raw_chunks} stored raw, {partial} partial (last) chunks"
    );
    if bad != 0 {
        std::process::exit(1);
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

use std::path::PathBuf;

use mm_raw::wof;

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetCompressionWorkSpaceSize(format: u16, buffer: *mut u32, fragment: *mut u32) -> i32;
    fn RtlCompressBuffer(
        format: u16,
        uncompressed: *const u8,
        uncompressed_len: u32,
        compressed: *mut u8,
        compressed_len: u32,
        chunk: u32,
        final_len: *mut u32,
        workspace: *mut u8,
    ) -> i32;
}

const XPRESS_HUFF_MAX: u16 = 0x0104;

fn compress_chunk(plain: &[u8], workspace: &mut [u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; plain.len() + 4096];
    let mut written: u32 = 0;
    let status = unsafe {
        RtlCompressBuffer(
            XPRESS_HUFF_MAX,
            plain.as_ptr(),
            plain.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            4096,
            &mut written,
            workspace.as_mut_ptr(),
        )
    };
    if status != 0 {
        return None;
    }
    out.truncate(written as usize);
    (out.len() < plain.len()).then_some(out)
}

fn main() {
    let path: PathBuf =
        std::env::args().nth(1).unwrap_or_else(|| r"C:\Windows\System32\notepad.exe".into()).into();
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("could not read {}: {err}", path.display());
            std::process::exit(2);
        }
    };
    println!("{} — {} bytes", path.display(), data.len());

    let mut buffer_ws: u32 = 0;
    let mut fragment_ws: u32 = 0;
    let status = unsafe {
        RtlGetCompressionWorkSpaceSize(XPRESS_HUFF_MAX, &mut buffer_ws, &mut fragment_ws)
    };
    if status != 0 {
        eprintln!("this Windows build will not compress Xpress Huffman (status {status:#010x})");
        std::process::exit(2);
    }
    let mut workspace = vec![0u8; buffer_ws as usize];

    let mut failures = 0;
    for (label, algorithm, chunk_size) in [
        ("XPRESS4K", wof::ALGORITHM_XPRESS4K, 4096usize),
        ("XPRESS8K", wof::ALGORITHM_XPRESS8K, 8192),
        ("XPRESS16K", wof::ALGORITHM_XPRESS16K, 16384),
    ] {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut stored_raw = 0;
        for piece in data.chunks(chunk_size) {
            match compress_chunk(piece, &mut workspace) {
                Some(compressed) => chunks.push(compressed),
                None => {
                    stored_raw += 1;
                    chunks.push(piece.to_vec());
                }
            }
        }

        let mut stream = Vec::new();
        let mut running = 0u32;
        for chunk in &chunks[..chunks.len().saturating_sub(1)] {
            running += chunk.len() as u32;
            stream.extend_from_slice(&running.to_le_bytes());
        }
        let table_bytes = stream.len();
        for chunk in &chunks {
            stream.extend_from_slice(chunk);
        }

        let backing = wof::Backing { provider: wof::WOF_PROVIDER_FILE, algorithm };
        let decoded = wof::decompress(&stream, data.len() as u64, backing, usize::MAX);

        print!(
            "{label:<10} {:>6} chunks, {stored_raw:>4} stored raw, table {table_bytes:>7} B, \
             stream {:>9} B  ->  ",
            chunks.len(),
            stream.len()
        );
        match decoded {
            Ok(got) if got == data => println!("identical, {} bytes", got.len()),
            Ok(got) => {
                failures += 1;
                let first = got.iter().zip(&data).position(|(a, b)| a != b);
                println!(
                    "MISMATCH: got {} bytes (wanted {}), first difference at {first:?}",
                    got.len(),
                    data.len()
                );
            }
            Err(why) => {
                failures += 1;
                println!("REFUSED: {why}");
            }
        }
    }

    let mut chunks = Vec::new();
    for piece in data.chunks(4096) {
        chunks.push(compress_chunk(piece, &mut workspace).unwrap_or_else(|| piece.to_vec()));
    }
    let mut stream = Vec::new();
    let mut running = 0u32;
    for chunk in &chunks[..chunks.len().saturating_sub(1)] {
        running += chunk.len() as u32;
        stream.extend_from_slice(&running.to_le_bytes());
    }
    for chunk in &chunks {
        stream.extend_from_slice(chunk);
    }
    let backing =
        wof::Backing { provider: wof::WOF_PROVIDER_FILE, algorithm: wof::ALGORITHM_XPRESS4K };
    for cap in [1usize, 4096, 4097, 100_000] {
        let cap = cap.min(data.len());
        match wof::decompress(&stream, data.len() as u64, backing, cap) {
            Ok(got) if got.len() == cap && got[..] == data[..cap] => {}
            other => {
                failures += 1;
                println!("capped read at {cap} bytes disagreed: {other:?}");
            }
        }
    }
    if failures == 0 {
        println!("capped reads at 1, 4096, 4097 and 100000 bytes all match the file's prefix");
    }

    if failures > 0 {
        eprintln!("\n{failures} check(s) failed");
        std::process::exit(1);
    }
    println!("\nThe decoder reproduces the file from Windows' own Xpress Huffman output.");
}

use mm_core::xpress;

pub const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;

pub const WOF_PROVIDER_WIM: u32 = 1;
pub const WOF_PROVIDER_FILE: u32 = 2;

pub const ALGORITHM_XPRESS4K: u32 = 0;
pub const ALGORITHM_LZX: u32 = 1;
pub const ALGORITHM_XPRESS8K: u32 = 2;
pub const ALGORITHM_XPRESS16K: u32 = 3;

pub const STREAM_NAME: &str = "WofCompressedData";

pub const MAX_OUTPUT: usize = 512 * 1024 * 1024;

const MAX_CHUNKS: usize = MAX_OUTPUT / 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backing {
    pub provider: u32,
    pub algorithm: u32,
}

impl Backing {
    #[must_use]
    pub fn is_file_provider(&self) -> bool {
        self.provider == WOF_PROVIDER_FILE
    }

    #[must_use]
    pub fn wim(&self) -> bool {
        self.provider == WOF_PROVIDER_WIM
    }

    #[must_use]
    pub fn chunk_size(&self) -> Option<usize> {
        if !self.is_file_provider() {
            return None;
        }
        match self.algorithm {
            ALGORITHM_XPRESS4K => Some(4096),
            ALGORITHM_LZX => Some(mm_core::lzx::CHUNK_SIZE),
            ALGORITHM_XPRESS8K => Some(8192),
            ALGORITHM_XPRESS16K => Some(16384),
            _ => None,
        }
    }

    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        if self.wim() {
            return "WIM-backed";
        }
        if !self.is_file_provider() {
            return "unknown WOF provider";
        }
        match self.algorithm {
            ALGORITHM_XPRESS4K => "XPRESS4K",
            ALGORITHM_LZX => "LZX",
            ALGORITHM_XPRESS8K => "XPRESS8K",
            ALGORITHM_XPRESS16K => "XPRESS16K",
            _ => "unknown WOF algorithm",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreadable {
    Lzx { chunk: usize, why: mm_core::lzx::Error },
    Wim,
    Unrecognised { provider: u32, algorithm: u32 },
    NoStream(String),
    BadChunkTable(String),
    ShortChunk { chunk: usize, got: usize, want: usize },
    TooLarge(u64),
    NoLength,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::Lzx { chunk, why } => write!(
                f,
                "the file is Compact-OS LZX compressed and chunk {chunk} did not decode: {why}"
            ),
            Unreadable::Wim => write!(
                f,
                "the file is Compact-OS backed by a WIM image elsewhere on the volume, so its \
                 bytes are not in the file itself"
            ),
            Unreadable::Unrecognised { provider, algorithm } => write!(
                f,
                "the file carries a Compact-OS (WOF) reparse point naming provider {provider} \
                 algorithm {algorithm}, which this build does not recognise"
            ),
            Unreadable::NoStream(why) => write!(
                f,
                "the file is Compact-OS compressed but its WofCompressedData stream {why}"
            ),
            Unreadable::BadChunkTable(why) => write!(
                f,
                "the file is Compact-OS compressed but its chunk table is not usable: {why}"
            ),
            Unreadable::ShortChunk { chunk, got, want } => write!(
                f,
                "Compact-OS chunk {chunk} decompressed to {got} bytes where the chunk table says \
                 {want}, so the file could not be reassembled"
            ),
            Unreadable::NoLength => write!(
                f,
                "the file carries a Compact-OS (WOF) reparse point but nothing on its \
                 record says how long it decompresses to, so its bytes could not be \
                 reassembled"
            ),
            Unreadable::TooLarge(size) => write!(
                f,
                "the file is Compact-OS compressed and its record claims {size} uncompressed \
                 bytes, past the {MAX_OUTPUT}-byte limit this build will decompress"
            ),
        }
    }
}

const MARKER: &str = "Compact-OS";

#[must_use]
pub fn describes_a_compact_os_failure(message: &str) -> bool {
    message.contains(MARKER)
}

#[must_use]
pub fn describes_lzx(message: &str) -> bool {
    message.contains(MARKER) && message.contains("LZX")
}

#[must_use]
pub fn parse_reparse(content: &[u8]) -> Option<Backing> {
    let tag = u32::from_le_bytes(content.get(0..4)?.try_into().ok()?);
    if tag != IO_REPARSE_TAG_WOF {
        return None;
    }
    let declared = u16::from_le_bytes(content.get(4..6)?.try_into().ok()?) as usize;
    let data = content.get(8..8usize.checked_add(declared)?)?;

    let _version = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?);
    let provider = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
    if provider != WOF_PROVIDER_FILE {
        return Some(Backing { provider, algorithm: u32::MAX });
    }
    let _provider_version = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?);
    let algorithm = u32::from_le_bytes(data.get(12..16)?.try_into().ok()?);
    Some(Backing { provider, algorithm })
}

pub fn decompress(
    stream: &[u8],
    uncompressed_size: u64,
    backing: Backing,
    max_bytes: usize,
) -> Result<Vec<u8>, Unreadable> {
    if backing.wim() {
        return Err(Unreadable::Wim);
    }
    let Some(chunk_size) = backing.chunk_size() else {
        return Err(Unreadable::Unrecognised {
            provider: backing.provider,
            algorithm: backing.algorithm,
        });
    };
    if uncompressed_size > MAX_OUTPUT as u64 {
        return Err(Unreadable::TooLarge(uncompressed_size));
    }
    let full_size = uncompressed_size as usize;
    if full_size == 0 {
        return Ok(Vec::new());
    }

    let chunks = full_size.div_ceil(chunk_size);
    if chunks > MAX_CHUNKS {
        return Err(Unreadable::BadChunkTable(format!(
            "{chunks} chunks is more than the {MAX_CHUNKS} this build will walk"
        )));
    }
    let entry_width: usize = if uncompressed_size > u64::from(u32::MAX) { 8 } else { 4 };
    let table_bytes = (chunks - 1) * entry_width;
    if stream.len() < table_bytes {
        return Err(Unreadable::BadChunkTable(format!(
            "the stream is {} bytes, shorter than the {table_bytes}-byte table {chunks} chunks \
             need",
            stream.len()
        )));
    }
    let (table, body) = stream.split_at(table_bytes);

    let wanted = full_size.min(max_bytes);
    let mut out: Vec<u8> = Vec::with_capacity(wanted.min(16 * 1024 * 1024));
    let lzx = backing.algorithm == ALGORITHM_LZX;
    let mut xpress_decoder = if lzx { None } else { Some(xpress::Decoder::new()) };
    let mut lzx_decoder = if lzx { Some(mm_core::lzx::Decoder::new()) } else { None };

    let offset_of = |i: usize| -> u64 {
        if i == 0 {
            return 0;
        }
        let at = (i - 1) * entry_width;
        if entry_width == 8 {
            u64::from_le_bytes(table[at..at + 8].try_into().unwrap_or([0; 8]))
        } else {
            u64::from(u32::from_le_bytes(table[at..at + 4].try_into().unwrap_or([0; 4])))
        }
    };

    let plain_len = |i: usize| -> usize {
        if i + 1 == chunks {
            match full_size - i * chunk_size {
                0 => chunk_size,
                rem => rem,
            }
        } else {
            chunk_size
        }
    };

    let span = |i: usize| -> (u64, u64) {
        (offset_of(i), if i + 1 == chunks { body.len() as u64 } else { offset_of(i + 1) })
    };
    for i in 0..chunks {
        let (start, end) = span(i);
        if end < start || end > body.len() as u64 {
            return Err(Unreadable::BadChunkTable(format!(
                "chunk {i} spans {start}..{end} of a {}-byte stream",
                body.len()
            )));
        }
        let held = end - start;
        if held == 0 || held > plain_len(i) as u64 {
            return Err(Unreadable::BadChunkTable(format!(
                "chunk {i} holds {held} bytes for {} bytes of file",
                plain_len(i)
            )));
        }
    }

    for i in 0..chunks {
        if out.len() >= wanted {
            break;
        }
        let (start, end) = span(i);
        let piece = &body[start as usize..end as usize];
        let plain_len = plain_len(i);

        if piece.len() == plain_len {
            out.extend_from_slice(piece);
            continue;
        }
        if let Some(decoder) = lzx_decoder.as_mut() {
            decoder
                .decompress_into(piece, plain_len, &mut out)
                .map_err(|why| Unreadable::Lzx { chunk: i, why })?;
            continue;
        }
        let decoder = xpress_decoder.as_mut().expect("one decoder or the other");
        let before = out.len();
        decoder.decompress_into(piece, plain_len, &mut out);
        let got = out.len() - before;
        if got != plain_len {
            return Err(Unreadable::ShortChunk { chunk: i, got, want: plain_len });
        }
    }

    out.truncate(wanted);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reparse(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    fn measured(algorithm: u32) -> Vec<u8> {
        let mut v = 1u32.to_le_bytes().to_vec();
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&algorithm.to_le_bytes());
        v
    }

    #[test]
    fn the_four_algorithm_numbers_windows_wrote_map_to_the_four_chunk_sizes() {
        let sizes: Vec<Option<usize>> = (0..4)
            .map(|a| {
                parse_reparse(&reparse(IO_REPARSE_TAG_WOF, &measured(a))).unwrap().chunk_size()
            })
            .collect();
        assert_eq!(sizes, vec![Some(4096), Some(32768), Some(8192), Some(16384)]);
    }

    #[test]
    fn a_non_wof_reparse_point_is_not_ours() {
        assert!(parse_reparse(&reparse(0xA000_0003, &[0u8; 16])).is_none());
        assert!(parse_reparse(&reparse(0x9000_001A, &[0u8; 16])).is_none());
    }

    #[test]
    fn a_wim_backed_file_is_named_rather_than_decoded() {
        let mut data = 1u32.to_le_bytes().to_vec();
        data.extend_from_slice(&WOF_PROVIDER_WIM.to_le_bytes());
        data.extend_from_slice(&[0u8; 16]);
        let backing = parse_reparse(&reparse(IO_REPARSE_TAG_WOF, &data)).unwrap();
        assert!(backing.wim());
        assert_eq!(decompress(&[], 4096, backing, usize::MAX), Err(Unreadable::Wim));
    }

    #[test]
    fn an_lzx_backed_file_reads_back_as_its_own_bytes() {
        const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");
        const PLAIN: u64 = 140_000;
        let backing =
            parse_reparse(&reparse(IO_REPARSE_TAG_WOF, &measured(ALGORITHM_LZX))).unwrap();
        assert_eq!(backing.chunk_size(), Some(32768));
        let out = decompress(STREAM, PLAIN, backing, usize::MAX).expect("decodes");
        assert_eq!(out.len() as u64, PLAIN);
        assert_ne!(out[..64], [0u8; 64]);
        assert_eq!(mm_core::FileHash::compute(&out).sha1_hex().unwrap(), PSEUDOCODE_SHA1);
    }

    const PSEUDOCODE_SHA1: &str = "df0ecca88a0aaddbd0ad196d528a1482e917dede";

    #[test]
    fn a_damaged_lzx_chunk_is_an_explicit_unknown_not_a_buffer_of_anything() {
        const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");
        let backing =
            parse_reparse(&reparse(IO_REPARSE_TAG_WOF, &measured(ALGORITHM_LZX))).unwrap();
        let mut damaged = STREAM.to_vec();
        damaged[600] ^= 0xff;
        damaged[900] ^= 0xff;
        let err = decompress(&damaged, 140_000, backing, usize::MAX).unwrap_err();
        assert!(matches!(err, Unreadable::Lzx { .. }), "{err:?}");
        let text = err.to_string();
        assert!(describes_lzx(&text), "{text}");
        assert!(describes_a_compact_os_failure(&text), "{text}");
    }

    #[test]
    fn a_truncated_reparse_point_is_refused_at_every_length() {
        let full = reparse(IO_REPARSE_TAG_WOF, &measured(ALGORITHM_XPRESS4K));
        for cut in 0..full.len() {
            assert!(
                parse_reparse(&full[..cut]).is_none(),
                "a {cut}-byte reparse point must not parse"
            );
        }
        assert!(parse_reparse(&full).is_some());
    }

    fn raw_stream(data: &[u8], chunk_size: usize) -> Vec<u8> {
        let chunks = data.len().div_ceil(chunk_size);
        let mut stream = Vec::new();
        for i in 1..chunks {
            stream.extend_from_slice(&((i * chunk_size) as u32).to_le_bytes());
        }
        stream.extend_from_slice(data);
        stream
    }

    fn file_backing() -> Backing {
        Backing { provider: WOF_PROVIDER_FILE, algorithm: ALGORITHM_XPRESS4K }
    }

    #[test]
    fn raw_chunks_round_trip_at_every_boundary() {
        for len in [1usize, 4095, 4096, 4097, 8192, 12289] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let stream = raw_stream(&data, 4096);
            let got = decompress(&stream, len as u64, file_backing(), usize::MAX).unwrap();
            assert_eq!(got, data, "length {len}");
        }
    }

    #[test]
    fn a_single_chunk_file_has_no_table_at_all() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let got = decompress(&data, 4096, file_backing(), usize::MAX).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn the_callers_cap_truncates_without_decoding_the_rest() {
        let data: Vec<u8> = (0..40960).map(|i| (i % 251) as u8).collect();
        let stream = raw_stream(&data, 4096);
        let got = decompress(&stream, data.len() as u64, file_backing(), 5000).unwrap();
        assert_eq!(got.len(), 5000);
        assert_eq!(got[..], data[..5000]);
    }

    #[test]
    fn a_chunk_table_pointing_backwards_is_refused() {
        let data: Vec<u8> = vec![7u8; 12288];
        let mut stream = raw_stream(&data, 4096);
        stream[0..4].copy_from_slice(&8192u32.to_le_bytes());
        stream[4..8].copy_from_slice(&4096u32.to_le_bytes());
        assert!(matches!(
            decompress(&stream, 12288, file_backing(), usize::MAX),
            Err(Unreadable::BadChunkTable(_))
        ));
    }

    #[test]
    fn a_chunk_table_pointing_past_the_stream_is_refused() {
        let data: Vec<u8> = vec![7u8; 12288];
        let mut stream = raw_stream(&data, 4096);
        stream[4..8].copy_from_slice(&0xffff_0000u32.to_le_bytes());
        assert!(matches!(
            decompress(&stream, 12288, file_backing(), usize::MAX),
            Err(Unreadable::BadChunkTable(_))
        ));
    }

    #[test]
    fn a_hostile_uncompressed_size_allocates_nothing() {
        let err =
            decompress(&[0u8; 16], 4 * 1024 * 1024 * 1024, file_backing(), usize::MAX).unwrap_err();
        assert!(matches!(err, Unreadable::TooLarge(_)));
        let err =
            decompress(&[0u8; 16], MAX_OUTPUT as u64, file_backing(), usize::MAX).unwrap_err();
        assert!(matches!(err, Unreadable::BadChunkTable(_)));
    }

    #[test]
    fn a_short_stream_for_the_declared_size_is_refused_not_padded() {
        let data: Vec<u8> = vec![3u8; 4096];
        let mut stream = 4096u32.to_le_bytes().to_vec();
        stream.extend_from_slice(&data);
        let err = decompress(&stream, 8192, file_backing(), usize::MAX).unwrap_err();
        assert!(matches!(err, Unreadable::BadChunkTable(_)), "{err:?}");
    }

    #[test]
    fn garbage_never_panics_or_hangs() {
        let data: Vec<u8> = (0..20000usize).map(|i| (i.wrapping_mul(37) % 256) as u8).collect();
        for algorithm in 0..6u32 {
            let backing = Backing { provider: WOF_PROVIDER_FILE, algorithm };
            for cut in (0..data.len()).step_by(97) {
                let _ = decompress(&data[..cut], 65536, backing, usize::MAX);
                let _ = decompress(&data[..cut], 0, backing, usize::MAX);
                let _ = decompress(&data[..cut], u64::MAX, backing, 4096);
            }
        }
    }

    #[test]
    fn every_way_of_failing_names_itself_as_compact_os() {
        let all = [
            Unreadable::Lzx { chunk: 3, why: mm_core::lzx::Error::Truncated },
            Unreadable::Wim,
            Unreadable::Unrecognised { provider: 9, algorithm: 9 },
            Unreadable::NoStream("is missing".into()),
            Unreadable::BadChunkTable("nonsense".into()),
            Unreadable::ShortChunk { chunk: 1, got: 0, want: 4096 },
            Unreadable::TooLarge(1 << 40),
        ];
        for why in all {
            assert!(
                describes_a_compact_os_failure(&why.to_string()),
                "{why:?} does not name itself: {why}"
            );
        }
        assert!(describes_lzx(
            &Unreadable::Lzx { chunk: 0, why: mm_core::lzx::Error::EmptyBlock }.to_string()
        ));
        assert!(!describes_lzx(&Unreadable::Wim.to_string()));
        assert!(!describes_a_compact_os_failure("some unrelated read error"));
    }

    #[test]
    fn a_zero_length_file_is_empty_rather_than_an_error() {
        assert_eq!(decompress(&[], 0, file_backing(), usize::MAX), Ok(Vec::new()));
    }
}

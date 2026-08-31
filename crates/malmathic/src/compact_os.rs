use mm_raw::wof;
use mm_sign::{TrustStore, Verdict};

use crate::testimage::{Builder, Presence};

pub(crate) fn raw_chunk_stream(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let chunks = data.len().div_ceil(chunk_size);
    let mut stream = Vec::new();
    for i in 1..chunks {
        stream.extend_from_slice(&((i * chunk_size) as u32).to_le_bytes());
    }
    stream.extend_from_slice(data);
    stream
}

fn volume_with(
    content: &[u8],
    algorithm: u32,
    stream: &[u8],
) -> mm_raw::Volume<std::io::Cursor<Vec<u8>>> {
    let mut builder = Builder::new();
    builder.compact_os_file(5, "payload.bin", content.len() as u64, algorithm, stream);
    builder.open()
}

#[test]
fn a_compact_os_file_reads_back_as_itself_through_the_ordinary_read_path() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);
    let volume = volume_with(&content, wof::ALGORITHM_XPRESS4K, &stream);

    assert_eq!(volume.read("\\payload.bin").unwrap(), content);
    let record = volume.resolve("\\payload.bin").unwrap();
    assert_eq!(volume.read_record_capped(record, usize::MAX).unwrap(), content);
}

#[test]
fn a_compact_os_file_read_without_wof_support_is_all_zeroes() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);
    let volume = volume_with(&content, wof::ALGORITHM_XPRESS4K, &stream);
    let record = volume.resolve("\\payload.bin").unwrap();

    let sparse = volume.fs().read_data_by_record(record, None, u64::MAX).unwrap();
    assert_eq!(sparse.len(), content.len());
    assert!(sparse.iter().all(|&b| b == 0), "the sparse $DATA must read as zeroes");
}

#[test]
fn every_chunk_size_reassembles_the_same_file() {
    let content: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    for (algorithm, chunk) in [
        (wof::ALGORITHM_XPRESS4K, 4096usize),
        (wof::ALGORITHM_XPRESS8K, 8192),
        (wof::ALGORITHM_XPRESS16K, 16384),
    ] {
        let stream = raw_chunk_stream(&content, chunk);
        let volume = volume_with(&content, algorithm, &stream);
        assert_eq!(volume.read("\\payload.bin").unwrap(), content, "algorithm {algorithm}");
    }
}

#[test]
fn an_lzx_file_reads_back_as_itself_through_the_ordinary_read_path() {
    const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");
    const PLAIN: usize = 140_000;
    const SHA1: &str = "df0ecca88a0aaddbd0ad196d528a1482e917dede";

    let mut builder = Builder::new();
    builder.compact_os_file(5, "payload.bin", PLAIN as u64, wof::ALGORITHM_LZX, STREAM);
    let volume = builder.open();

    let out = volume.read("\\payload.bin").expect("LZX now decodes");
    assert_eq!(out.len(), PLAIN);
    assert_eq!(mm_core::FileHash::compute(&out).sha1_hex().unwrap(), SHA1);
    let record = volume.resolve("\\payload.bin").unwrap();
    assert_eq!(volume.read_record_capped(record, usize::MAX).unwrap().len(), PLAIN);
}

#[test]
fn a_damaged_lzx_file_is_an_error_rather_than_plausible_bytes() {
    const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");
    let mut damaged = STREAM.to_vec();
    damaged[600] ^= 0xff;
    damaged[900] ^= 0xff;

    let mut builder = Builder::new();
    builder.compact_os_file(5, "payload.bin", 140_000, wof::ALGORITHM_LZX, &damaged);
    let volume = builder.open();

    let err = volume.read("\\payload.bin").unwrap_err().to_string();
    assert!(err.contains("LZX"), "{err}");
    assert!(wof::describes_a_compact_os_failure(&err), "{err}");
    assert!(mm_score::compact_os_failure_is_recognised(&err), "{err}");
}

#[test]
fn the_cap_still_caps() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);
    let volume = volume_with(&content, wof::ALGORITHM_XPRESS4K, &stream);

    let head = volume.read_capped("\\payload.bin", 1000).unwrap();
    assert_eq!(head.len(), 1000);
    assert_eq!(head[..], content[..1000]);
}

#[test]
fn an_ordinary_file_on_the_same_volume_is_untouched() {
    let mut builder = Builder::new();
    let plain = b"MZ this is an ordinary file".to_vec();
    builder.file(5, "plain.bin", &plain, Presence::Live);
    let compressed: Vec<u8> = (0..9000).map(|i| (i % 251) as u8).collect();
    builder.compact_os_file(
        5,
        "packed.bin",
        compressed.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &raw_chunk_stream(&compressed, 4096),
    );
    let volume = builder.open();

    assert_eq!(volume.read("\\plain.bin").unwrap(), plain);
    assert_eq!(volume.read("\\packed.bin").unwrap(), compressed);
}

#[test]
fn every_unreadable_reason_is_recognised_by_the_scorer() {
    let reasons = [
        wof::Unreadable::Lzx { chunk: 3, why: mm_core::lzx::Error::Truncated },
        wof::Unreadable::Wim,
        wof::Unreadable::Unrecognised { provider: 9, algorithm: 9 },
        wof::Unreadable::NoStream("could not be read".into()),
        wof::Unreadable::BadChunkTable("short".into()),
        wof::Unreadable::ShortChunk { chunk: 1, got: 2, want: 3 },
        wof::Unreadable::TooLarge(1 << 40),
        wof::Unreadable::NoLength,
    ];
    for reason in reasons {
        let text = reason.to_string();
        assert!(
            wof::describes_a_compact_os_failure(&text),
            "mm-raw does not recognise its own message: {text}"
        );
        assert!(
            mm_score::compact_os_failure_is_recognised(&text),
            "mm-score would not price this as a Compact-OS failure: {text}"
        );
    }
    assert!(!mm_score::compact_os_failure_is_recognised("CatRoot could not be read"));
}

#[test]
fn the_mft_walk_sees_the_compression_for_every_algorithm() {
    for (algorithm, name, decodable) in [
        (wof::ALGORITHM_XPRESS4K, "XPRESS4K", true),
        (wof::ALGORITHM_XPRESS8K, "XPRESS8K", true),
        (wof::ALGORITHM_XPRESS16K, "XPRESS16K", true),
        (wof::ALGORITHM_LZX, "LZX", true),
    ] {
        let content: Vec<u8> = (0..9_000).map(|i| (i % 251) as u8).collect();
        let mut builder = Builder::new();
        builder.file(5, "plain.bin", b"MZ ordinary", Presence::Live);
        builder.compact_os_file(
            5,
            "payload.bin",
            content.len() as u64,
            algorithm,
            &raw_chunk_stream(&content, 4096),
        );
        let volume = builder.open();

        let mut seen = None;
        let mut plain = 0usize;
        mm_harvest::filesystem::enumerate(&volume, &mut |path, facts| {
            if path.key().ends_with("payload.bin") {
                seen = facts.compact_os;
            } else if facts.compact_os.is_none() {
                plain += 1;
            }
        })
        .expect("the walk completes");

        let backing = seen.unwrap_or_else(|| panic!("{name}: the walk did not see the backing"));
        assert_eq!(backing.algorithm_name(), name);
        assert!(backing.is_file_provider());
        assert_eq!(backing.chunk_size().is_some(), decodable, "{name}");
        assert!(plain > 0, "{name}: nothing else on the volume was enumerated at all");
    }
}

#[test]
fn a_compressed_payload_is_priced_end_to_end_from_the_volume() {
    use mm_core::{
        ArtifactSource, Candidate, CandidateId, Observation, ObservationKind, SignatureStatus,
    };
    use mm_score::baseline::BaselineBuilder;

    const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");
    let mut damaged = STREAM.to_vec();
    damaged[600] ^= 0xff;

    let mut builder = Builder::new();
    builder.file(5, "plain.exe", b"MZ ordinary", Presence::Live);
    builder.compact_os_file(5, "payload.exe", 140_000, wof::ALGORITHM_LZX, &damaged);
    let volume = builder.open();

    let reason = volume.read("\\payload.exe").unwrap_err().to_string();

    let mut census = BaselineBuilder::new();
    let mut observations = Vec::new();
    mm_harvest::filesystem::enumerate(&volume, &mut |path, facts| {
        census.observe_file(path, facts.compact_os.is_some());
        if path.key().ends_with("payload.exe") {
            observations.extend(mm_harvest::filesystem::observations_for(path, facts));
        }
    })
    .expect("the walk completes");

    for i in 0..12_000 {
        census.observe_file(
            &mm_core::NormalizedPath::parse(&format!(r"C:\Windows\System32\f{i}.dll")).unwrap(),
            false,
        );
    }
    let baseline = census.build();
    assert_eq!(baseline.compact_os_executables(), 1, "the walk did not feed the census");

    let path = mm_core::NormalizedPath::parse(r"\payload.exe").unwrap();
    const PRIOR_IS_IRRELEVANT_HERE: f64 = -7.67;
    let mut candidate = Candidate::new(CandidateId(0), PRIOR_IS_IRRELEVANT_HERE);
    candidate.path = Some(path.clone());
    for observation in observations {
        candidate.observe(observation);
    }
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        path,
        ObservationKind::Signature(SignatureStatus::Unknown { reason }),
    ));
    let evidence = mm_score::extract(&candidate, &baseline, &mm_score::Weights::embedded());
    let priced =
        evidence.iter().find(|e| e.feature == "compact_os_compressed_executable").unwrap_or_else(
            || panic!("the compression reached nothing that could price it: {evidence:#?}"),
        );
    assert!(priced.log_lr > 0.0);
    assert!(priced.detail.contains("LZX"), "{}", priced.detail);
}

#[test]
fn a_readable_lzx_payload_is_not_priced_for_being_compressed() {
    use mm_core::{Candidate, CandidateId};
    use mm_score::baseline::BaselineBuilder;

    const STREAM: &[u8] = include_bytes!("../../mm-core/fixtures/lzx/pseudocode.lzxstream");

    let mut builder = Builder::new();
    builder.file(5, "plain.exe", b"MZ ordinary", Presence::Live);
    builder.compact_os_file(5, "payload.exe", 140_000, wof::ALGORITHM_LZX, STREAM);
    let volume = builder.open();
    assert_eq!(volume.read("\\payload.exe").unwrap().len(), 140_000);

    let mut census = BaselineBuilder::new();
    let mut observations = Vec::new();
    mm_harvest::filesystem::enumerate(&volume, &mut |path, facts| {
        census.observe_file(path, facts.compact_os.is_some());
        if path.key().ends_with("payload.exe") {
            observations.extend(mm_harvest::filesystem::observations_for(path, facts));
        }
    })
    .expect("the walk completes");
    for i in 0..12_000 {
        census.observe_file(
            &mm_core::NormalizedPath::parse(&format!(r"C:\Windows\System32\f{i}.dll")).unwrap(),
            false,
        );
    }
    let baseline = census.build();
    assert_eq!(baseline.compact_os_executables(), 1);

    const PRIOR_IS_IRRELEVANT_HERE: f64 = -7.67;
    let mut candidate = Candidate::new(CandidateId(0), PRIOR_IS_IRRELEVANT_HERE);
    candidate.path = Some(mm_core::NormalizedPath::parse(r"\payload.exe").unwrap());
    for observation in observations {
        candidate.observe(observation);
    }
    let evidence = mm_score::extract(&candidate, &baseline, &mm_score::Weights::embedded());
    assert!(
        !evidence.iter().any(|e| e.feature == "compact_os_compressed_executable"),
        "a file this build can read must not be charged for how it is stored: {evidence:#?}"
    );
}

#[test]
fn the_mft_walk_leaves_ordinary_files_alone() {
    let mut builder = Builder::new();
    builder.file(5, "plain.bin", b"MZ ordinary", Presence::Live);
    let volume = builder.open();

    let mut compressed = 0usize;
    let mut total = 0usize;
    mm_harvest::filesystem::enumerate(&volume, &mut |_, facts| {
        total += 1;
        if facts.compact_os.is_some() {
            compressed += 1;
        }
    })
    .expect("the walk completes");
    assert!(total > 0);
    assert_eq!(compressed, 0);
}

#[test]
fn the_carve_path_accounts_for_the_clusters_the_bytes_are_really_in() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);
    let volume = volume_with(&content, wof::ALGORITHM_XPRESS4K, &stream);
    let record = volume.resolve("\\payload.bin").unwrap();

    let wof_runs = volume.data_runs(record);
    assert!(
        !wof_runs.is_empty(),
        "a Compact-OS file's bytes are in clusters, and must be reported"
    );
    let plain_runs = volume.fs().runs_by_record(record, None).unwrap_or_default();
    assert!(
        plain_runs.iter().all(|r| r.lcn.is_none()),
        "the unnamed $DATA is nothing but holes, which is what made this necessary"
    );
}

#[cfg(windows)]
mod windows_compressor {
    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetCompressionWorkSpaceSize(format: u16, buffer: *mut u32, fragment: *mut u32)
            -> i32;
        #[allow(clippy::too_many_arguments)]
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

    pub fn wof_stream(data: &[u8], chunk_size: usize) -> Option<Vec<u8>> {
        let mut buffer_ws = 0u32;
        let mut fragment_ws = 0u32;
        let status = unsafe {
            RtlGetCompressionWorkSpaceSize(XPRESS_HUFF_MAX, &mut buffer_ws, &mut fragment_ws)
        };
        if status != 0 {
            return None;
        }
        let mut workspace = vec![0u8; buffer_ws as usize];

        let mut chunks: Vec<Vec<u8>> = Vec::new();
        for piece in data.chunks(chunk_size) {
            let mut out = vec![0u8; piece.len() + 4096];
            let mut written = 0u32;
            let status = unsafe {
                RtlCompressBuffer(
                    XPRESS_HUFF_MAX,
                    piece.as_ptr(),
                    piece.len() as u32,
                    out.as_mut_ptr(),
                    out.len() as u32,
                    4096,
                    &mut written,
                    workspace.as_mut_ptr(),
                )
            };
            out.truncate(written as usize);
            if status != 0 || out.len() >= piece.len() {
                chunks.push(piece.to_vec());
            } else {
                chunks.push(out);
            }
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
        Some(stream)
    }
}

#[cfg(windows)]
const SIGNED_BINARY: &str = r"C:\Windows\System32\ntdll.dll";

#[cfg(windows)]
#[test]
fn a_wof_compressed_microsoft_binary_verifies_as_valid_through_the_volume() {
    let Ok(original) = std::fs::read(SIGNED_BINARY) else { return };
    let Some(stream) = windows_compressor::wof_stream(&original, 4096) else { return };

    let trust = TrustStore::embedded();
    let baseline = mm_sign::verify_embedded(&original, &trust);
    assert!(
        matches!(baseline, Verdict::Valid { .. }),
        "the fixture binary must verify when read normally, or this test is vacuous: {}",
        baseline.describe()
    );

    let volume = volume_with(&original, wof::ALGORITHM_XPRESS4K, &stream);
    let read_back = volume.read("\\payload.bin").expect("a Compact-OS file must read");

    assert_eq!(read_back.len(), original.len());
    assert!(read_back == original, "the bytes off the volume must be the file itself");

    let verdict = mm_sign::verify_embedded(&read_back, &trust);
    assert!(
        matches!(verdict, Verdict::Valid { .. }),
        "a WOF-compressed Microsoft binary read through mm_raw::Volume must verify, got: {}",
        verdict.describe()
    );

    let sparse_bytes = vec![0u8; original.len()];
    let broken = mm_sign::verify_embedded(&sparse_bytes, &trust);
    assert!(
        broken.describe().contains("not a PE image"),
        "the pre-fix behaviour was the zero buffer failing to parse, got: {}",
        broken.describe()
    );
}

#[cfg(windows)]
#[test]
fn every_chunk_size_reassembles_a_real_binary_windows_compressed() {
    let Ok(original) = std::fs::read(SIGNED_BINARY) else { return };
    for (algorithm, chunk) in [
        (wof::ALGORITHM_XPRESS4K, 4096usize),
        (wof::ALGORITHM_XPRESS8K, 8192),
        (wof::ALGORITHM_XPRESS16K, 16384),
    ] {
        let Some(stream) = windows_compressor::wof_stream(&original, chunk) else { return };
        assert!(
            stream.len() < original.len(),
            "the fixture must actually be compressed, or it only tests raw storage"
        );
        let volume = volume_with(&original, algorithm, &stream);
        let got = volume.read("\\payload.bin").expect("a Compact-OS file must read");
        assert!(got == original, "algorithm {algorithm} did not reassemble the file");
    }
}

fn base_record_attributes(
    volume: &mm_raw::Volume<std::io::Cursor<Vec<u8>>>,
    record: u64,
) -> Vec<u32> {
    let bytes = volume.fs().read_record(record).expect("the record reads");
    let header = ntfs_core::MftRecordHeader::parse(&bytes).expect("it is a record");
    ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize)
        .expect("its attributes parse")
        .iter()
        .map(|a| a.type_code)
        .collect()
}

fn base_carries(
    volume: &mm_raw::Volume<std::io::Cursor<Vec<u8>>>,
    record: u64,
    type_code: u32,
    name: Option<&str>,
) -> bool {
    let bytes = volume.fs().read_record(record).expect("the record reads");
    let header = ntfs_core::MftRecordHeader::parse(&bytes).expect("it is a record");
    ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize)
        .expect("its attributes parse")
        .iter()
        .any(|a| a.type_code == type_code && a.name.as_deref() == name)
}

#[test]
fn a_wof_reparse_point_in_an_extension_record_is_not_read_as_zeroes() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let record = builder.compact_os_file(
        5,
        "payload.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_reparse_point(record);
    let volume = builder.open();

    let base = base_record_attributes(&volume, record);
    assert!(!base.contains(&0xC0), "the $REPARSE_POINT did not leave the base record: {base:02X?}");
    assert!(base.contains(&0x20), "no $ATTRIBUTE_LIST was left behind: {base:02X?}");
    assert!(base.contains(&0x80), "the $DATA was supposed to stay: {base:02X?}");

    let sparse = volume.fs().read_data_by_record(record, None, u64::MAX).unwrap();
    assert_eq!(sparse.len(), content.len());
    assert!(sparse.iter().all(|&b| b == 0), "the sparse $DATA must read as zeroes");

    let (backing, size) =
        volume.wof_backing(record).expect("the reparse point is in an extension record, not gone");
    assert!(backing.is_file_provider());
    assert_eq!(size, content.len() as u64);

    assert_eq!(volume.read("\\payload.bin").unwrap(), content);
    assert_eq!(volume.read_record_capped(record, usize::MAX).unwrap(), content);
}

#[test]
fn a_wof_unnamed_data_in_an_extension_record_still_gives_the_real_length() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let record = builder.compact_os_file(
        5,
        "payload.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_unnamed_data(record);
    builder.set_file_name_size(record, 0);
    let volume = builder.open();

    let base = base_record_attributes(&volume, record);
    assert!(base.contains(&0xC0), "the reparse point was supposed to stay: {base:02X?}");
    assert!(base.contains(&0x20), "no $ATTRIBUTE_LIST was left behind: {base:02X?}");
    assert!(
        !base_carries(&volume, record, 0x80, None),
        "the unnamed $DATA did not leave the base record: {base:02X?}"
    );
    assert!(
        base_carries(&volume, record, 0x80, Some(wof::STREAM_NAME)),
        "WofCompressedData was supposed to stay in the base record: {base:02X?}"
    );

    let (_, size) = volume.wof_backing(record).expect("the reparse point is in the base record");
    assert_eq!(size, content.len() as u64, "the length came from the wrong place");
    assert_eq!(volume.read("\\payload.bin").unwrap(), content);
}

#[test]
fn a_wof_file_with_nothing_left_in_its_base_record_still_reads() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let record = builder.compact_os_file(
        5,
        "payload.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_reparse_point(record);
    builder.spill_unnamed_data(record);
    builder.spill_named_stream(record, wof::STREAM_NAME);
    let volume = builder.open();

    let base = base_record_attributes(&volume, record);
    assert!(!base.contains(&0xC0), "the reparse point is still here: {base:02X?}");
    assert!(!base.contains(&0x80), "a $DATA is still here: {base:02X?}");

    assert_eq!(volume.read("\\payload.bin").unwrap(), content);
}

#[test]
fn a_misdirected_attribute_list_does_not_borrow_another_files_backing() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let victim = builder.compact_os_file(
        5,
        "victim.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    let neighbour = builder.compact_os_file(
        5,
        "neighbour.bin",
        content.len() as u64,
        wof::ALGORITHM_LZX,
        &stream,
    );
    builder.spill_reparse_point(victim);
    builder.misdirect_spilled_attributes(victim, neighbour);
    let volume = builder.open();

    let sparse = volume.fs().read_data_by_record(victim, None, u64::MAX).unwrap();
    assert_eq!(sparse.len(), content.len());
    assert!(sparse.iter().all(|&b| b == 0), "the sparse $DATA must read as zeroes");

    assert!(
        volume.wof_backing(victim).is_none(),
        "the follower adopted a record that never said it belonged to this file"
    );
    let err = volume.read(r"\victim.bin").unwrap_err().to_string();
    assert!(mm_raw::describes_an_unaccounted_attribute_list(&err), "{err}");
    assert!(volume.read_record_capped(victim, usize::MAX).is_err());
}

#[test]
fn the_carve_path_follows_the_stream_even_when_the_reparse_point_spilled() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let record = builder.compact_os_file(
        5,
        "payload.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_reparse_point(record);
    let volume = builder.open();

    let runs = volume.data_runs(record);
    assert!(!runs.is_empty(), "a Compact-OS file's bytes are in clusters, and must be reported");
    assert!(runs.iter().all(|r| r.lcn.is_some()), "the carver was handed holes: {runs:?}");
    let stream_runs = volume.fs().runs_by_record(record, Some(wof::STREAM_NAME)).unwrap();
    assert_eq!(
        runs.iter().map(|r| (r.lcn, r.length)).collect::<Vec<_>>(),
        stream_runs.iter().map(|r| (r.lcn, r.length)).collect::<Vec<_>>()
    );
}

#[test]
fn a_record_whose_name_spilled_refuses_to_identify_itself_rather_than_guessing() {
    let mut builder = Builder::new();
    let record = builder.file(5, "payload.bin", b"MZ ordinary", Presence::Live);
    builder.spill_file_name(record);
    let volume = builder.open();

    let base = base_record_attributes(&volume, record);
    assert!(!base.contains(&0x30), "the $FILE_NAME did not leave the base record: {base:02X?}");
    assert!(
        volume.record_identity(record).is_none(),
        "an unnamed base record must refuse to identify itself, never guess"
    );
}

#[test]
fn an_extension_record_does_not_identify_itself_as_the_file_it_belongs_to() {
    let mut builder = Builder::new();
    let record = builder.file(5, "payload.bin", b"MZ ordinary", Presence::Live);
    builder.spill_file_name(record);
    let volume = builder.open();

    let extension = (record + 1..record + 8)
        .find(|n| {
            volume.fs().read_record(*n).ok().is_some_and(|bytes| {
                ntfs_core::MftRecordHeader::parse(&bytes)
                    .is_ok_and(|h| &h.signature == b"FILE" && !h.is_base_record())
            })
        })
        .expect("the spill wrote an extension record");

    assert!(
        volume.record_identity(extension).is_none(),
        "an extension record answered as though it were the file that owns it"
    );
}

#[test]
fn following_the_attribute_list_costs_nothing_when_nothing_spilled() {
    let content: Vec<u8> = (0..9_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let plain = builder.file(5, "plain.bin", b"MZ ordinary", Presence::Live);
    let packed = builder.compact_os_file(
        5,
        "packed.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    let spilled = builder.compact_os_file(
        5,
        "spilled.bin",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    builder.spill_reparse_point(spilled);
    let (volume, meter) = crate::hostile_index::metered(builder);

    let cost = |f: &dyn Fn()| {
        let before = meter.snapshot();
        f();
        meter.snapshot().since(&before).reads
    };
    let one_record = cost(&|| {
        volume.fs().read_record(plain).expect("the record reads");
    });
    assert!(one_record > 0, "the meter is not counting");

    assert_eq!(
        cost(&|| {
            let _ = volume.wof_backing(plain);
        }),
        one_record,
        "an ordinary file paid for a record it did not need"
    );
    assert_eq!(
        cost(&|| {
            let _ = volume.wof_backing(packed);
        }),
        one_record,
        "an unspilled Compact-OS file paid for the follow"
    );

    let spilled_cost = cost(&|| {
        let _ = volume.wof_backing(spilled);
    });
    assert_eq!(
        spilled_cost,
        one_record * 3,
        "the follow cost {spilled_cost} reads against {one_record} for a record"
    );
}

#[test]
fn a_wof_file_whose_length_cannot_be_established_is_an_error_rather_than_a_short_read() {
    let content: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let victim = builder.compact_os_file(5, "victim.bin", 0, wof::ALGORITHM_XPRESS4K, &stream);
    let volume = builder.open();

    assert!(base_carries(&volume, victim, 0xC0, None));
    assert!(!base_carries(&volume, victim, 0x20, None), "nothing was supposed to spill");
    assert!(volume.wof_backing(victim).is_none(), "a length was invented from the zeroes");

    let err = volume.read(r"\victim.bin").unwrap_err().to_string();
    assert!(wof::describes_a_compact_os_failure(&err), "{err}");
    assert!(err.contains("how long"), "{err}");
    assert!(mm_score::compact_os_failure_is_recognised(&err), "{err}");
}

fn spilled_reparse_volume(spill: bool) -> (mm_raw::Volume<std::io::Cursor<Vec<u8>>>, Vec<u8>) {
    let content: Vec<u8> = (0..9_000).map(|i| (i % 251) as u8).collect();
    let stream = raw_chunk_stream(&content, 4096);

    let mut builder = Builder::new();
    let dir = builder.directories(5, r"Program Files\Vendor");
    builder.compact_os_file(
        dir,
        "sibling.exe",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    let payload = builder.compact_os_file(
        dir,
        "payload.exe",
        content.len() as u64,
        wof::ALGORITHM_XPRESS4K,
        &stream,
    );
    if spill {
        builder.spill_reparse_point(payload);
    }
    builder.file(5, "plain.bin", b"MZ ordinary", Presence::Live);
    (builder.open(), content)
}

fn walk_backings(volume: &mm_raw::Volume<std::io::Cursor<Vec<u8>>>) -> Vec<(String, bool)> {
    let mut seen = Vec::new();
    mm_harvest::filesystem::enumerate(volume, &mut |path, facts| {
        seen.push((path.key().to_string(), facts.compact_os.is_some()));
    })
    .expect("the walk completes");
    seen.sort();
    seen
}

#[test]
fn a_spilled_reparse_point_does_not_change_what_the_walk_sees() {
    let (plain, _) = spilled_reparse_volume(false);
    let (spilled, _) = spilled_reparse_volume(true);

    let plain_seen = walk_backings(&plain);
    let spilled_seen = walk_backings(&spilled);

    assert_eq!(
        plain_seen, spilled_seen,
        "moving a $REPARSE_POINT into an extension record changed what the walk reports"
    );
    let compressed: Vec<&String> =
        spilled_seen.iter().filter(|(_, backed)| *backed).map(|(p, _)| p).collect();
    assert_eq!(
        compressed.len(),
        2,
        "both files in that directory are Compact-OS compressed: {spilled_seen:?}"
    );
}

#[test]
fn the_spilled_reparse_point_record_never_lost_its_name() {
    let (volume, _) = spilled_reparse_volume(true);
    let mut seen = Vec::new();
    let report = mm_harvest::filesystem::enumerate(&volume, &mut |path, _| {
        seen.push(path.key().to_string());
    })
    .expect("the walk completes");

    assert!(
        seen.iter().any(|k| k.ends_with("payload.exe")),
        "the base record named itself and the walk emitted it: {seen:?}"
    );
    assert_eq!(
        report.names_recovered, 0,
        "no name had to be recovered; the name was never anywhere else"
    );
    assert_eq!(report.unparsable, 0, "nothing failed to parse");
    assert_eq!(
        report.attribute_lists_seen, 1,
        "exactly one record spilled anything, and the run says so"
    );
}

#[test]
fn a_spilled_reparse_point_does_not_make_a_neighbour_look_lonely() {
    use mm_core::NormalizedPath;
    use mm_score::baseline::BaselineBuilder;

    for spill in [false, true] {
        let (volume, _) = spilled_reparse_volume(spill);
        let mut census = BaselineBuilder::new();
        mm_harvest::filesystem::enumerate(&volume, &mut |path, facts| {
            census.observe_file(path, facts.compact_os.is_some());
        })
        .expect("the walk completes");
        let baseline = census.build();

        assert_eq!(
            baseline.compact_os_files(),
            2,
            "spill={spill}: the volume holds two Compact-OS files"
        );
        assert_eq!(
            baseline.compact_os_executables(),
            2,
            "spill={spill}: both of them are executables"
        );
        for name in ["payload.exe", "sibling.exe"] {
            let path = NormalizedPath::parse(&format!(r"\Program Files\Vendor\{name}"))
                .expect("the path parses");
            assert_eq!(
                baseline.is_lone_compact_os_file(&path),
                Some(false),
                "spill={spill}: {name} is not the only compressed file in its directory"
            );
        }
    }
}

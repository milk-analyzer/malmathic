use std::io::{Read, Seek, Write};

use mm_raw::{wof, Volume};

const MAGIC: &[u8; 8] = b"MMLZXCAP";
const VERSION: u32 = 1;
const MAX_SAMPLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_SAMPLES: u32 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub path: String,
    pub provider: u32,
    pub algorithm: u32,
    pub declared: u64,
    pub stream: Vec<u8>,
    pub plain: Vec<u8>,
}

pub fn consistent_chunk_sizes(sample: &Sample) -> Vec<usize> {
    let mut out = Vec::new();
    for candidate in [4096usize, 8192, 16384, 32768, 65536, 131_072] {
        let chunks = (sample.declared as usize).div_ceil(candidate).max(1);
        let table = (chunks - 1) * 4;
        if table >= sample.stream.len() {
            continue;
        }
        let mut previous = 0u32;
        let mut ok = true;
        for i in 0..chunks - 1 {
            let Some(slice) = sample.stream.get(i * 4..i * 4 + 4) else {
                ok = false;
                break;
            };
            let offset = u32::from_le_bytes(slice.try_into().unwrap_or([0; 4]));
            if offset <= previous || (table as u64 + u64::from(offset)) > sample.stream.len() as u64
            {
                ok = false;
                break;
            }
            previous = offset;
        }
        if ok {
            out.push(candidate);
        }
    }
    out
}

pub fn write_capture(samples: &[Sample]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(samples.len() as u32).to_le_bytes());
    for sample in samples {
        let path = sample.path.as_bytes();
        out.extend_from_slice(&(path.len() as u32).to_le_bytes());
        out.extend_from_slice(path);
        out.extend_from_slice(&sample.provider.to_le_bytes());
        out.extend_from_slice(&sample.algorithm.to_le_bytes());
        out.extend_from_slice(&sample.declared.to_le_bytes());
        out.extend_from_slice(&(sample.stream.len() as u64).to_le_bytes());
        out.extend_from_slice(&sample.stream);
        out.extend_from_slice(&(sample.plain.len() as u64).to_le_bytes());
        out.extend_from_slice(&sample.plain);
        out.extend_from_slice(&sha256_of(&sample.plain));
    }
    out
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let hash = mm_core::hash::FileHash::compute(bytes);
    if let Some(hex) = hash.sha256_hex() {
        for (i, slot) in digest.iter_mut().enumerate() {
            let Some(pair) = hex.get(i * 2..i * 2 + 2) else { break };
            *slot = u8::from_str_radix(pair, 16).unwrap_or(0);
        }
    }
    digest
}

pub fn read_capture(bytes: &[u8]) -> Option<Vec<Sample>> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let slice = bytes.get(at..at.checked_add(n)?)?;
        at += n;
        Some(slice)
    };
    if take(8)? != MAGIC {
        return None;
    }
    if u32::from_le_bytes(take(4)?.try_into().ok()?) != VERSION {
        return None;
    }
    let count = u32::from_le_bytes(take(4)?.try_into().ok()?);
    if count > MAX_SAMPLES {
        return None;
    }
    let mut samples = Vec::new();
    for _ in 0..count {
        let path_len = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let path = String::from_utf8_lossy(take(path_len)?).into_owned();
        let provider = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let algorithm = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let declared = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let stream_len = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;
        let stream = take(stream_len)?.to_vec();
        let plain_len = usize::try_from(u64::from_le_bytes(take(8)?.try_into().ok()?)).ok()?;
        let plain = take(plain_len)?.to_vec();
        let _digest = take(32)?;
        samples.push(Sample { path, provider, algorithm, declared, stream, plain });
    }
    Some(samples)
}

pub fn describe<W: Write>(bytes: &[u8], label: &str, out: &mut W) -> std::io::Result<bool> {
    let Some(samples) = read_capture(bytes) else {
        writeln!(out, "{label} is not a capture this build understands")?;
        return Ok(false);
    };
    writeln!(out, "{label}: {} sample(s), {} bytes", samples.len(), bytes.len())?;
    for sample in &samples {
        let fits = consistent_chunk_sizes(sample);
        writeln!(
            out,
            "\n  {}\n    provider {}, algorithm {}, declared {} bytes, stream {} bytes, \
             plaintext {} bytes",
            sample.path,
            sample.provider,
            sample.algorithm,
            sample.declared,
            sample.stream.len(),
            sample.plain.len()
        )?;
        writeln!(out, "    chunk sizes the bytes are consistent with: {fits:?}")?;
        if fits.len() == 1 {
            writeln!(out, "    -> {} bytes, and only that, fits this sample", fits[0])?;
        } else if fits.is_empty() {
            writeln!(
                out,
                "    -> NO candidate fits. Either the table is not four-byte little-endian \
                 offsets from the end of the table, or this stream is not laid out the way \
                 `mm_raw::wof` believes."
            )?;
        }
        write!(out, "    stream head:")?;
        for byte in sample.stream.iter().take(32) {
            write!(out, " {byte:02x}")?;
        }
        writeln!(out)?;
        write!(out, "    plaintext head:")?;
        for byte in sample.plain.iter().take(16) {
            write!(out, " {byte:02x}")?;
        }
        writeln!(out)?;
    }
    let lzx: Vec<&Sample> = samples.iter().filter(|s| s.algorithm == wof::ALGORITHM_LZX).collect();
    if let Some(first) = lzx.first() {
        let mut common = consistent_chunk_sizes(first);
        for sample in &lzx[1..] {
            let fits = consistent_chunk_sizes(sample);
            common.retain(|c| fits.contains(c));
        }
        writeln!(out, "\nchunk size(s) consistent with ALL {} LZX samples: {common:?}", lzx.len())?;
    }
    Ok(true)
}

#[derive(Clone, Debug, Default)]
pub struct CaptureOutcome {
    pub samples: Vec<Sample>,
    pub seen: usize,
    pub refused_no_stream: usize,
    pub refused_wrong_length: usize,
    pub refused_zeroes_or_junk: usize,
}

#[derive(Clone, Debug)]
pub struct CaptureOptions<'a> {
    pub mount: &'a str,
    pub any_algorithm: bool,
    pub limit: usize,
}

pub fn refuses_to_write_onto(mount: &str, out_path: &std::path::Path) -> bool {
    let root = mount.trim_end_matches(['\\', '/']).to_lowercase();
    if root.is_empty() {
        return false;
    }
    let target = out_path.display().to_string().to_lowercase().replace('/', "\\");
    target == root || target.starts_with(&format!("{root}\\"))
}

pub fn capture<R: Read + Seek, W: Write>(
    volume: &Volume<R>,
    options: &CaptureOptions<'_>,
    out: &mut W,
) -> std::io::Result<CaptureOutcome> {
    let mut outcome = CaptureOutcome::default();

    let mut stack: Vec<(String, usize)> = vec![(String::new(), 0)];
    while let Some((prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH || outcome.samples.len() >= options.limit {
            continue;
        }
        for entry in volume.list_directory_entries(&prefix) {
            if outcome.samples.len() >= options.limit {
                break;
            }
            let key = format!("{prefix}\\{}", entry.name);
            let children = volume.list_directory_entries(&key.to_lowercase());
            if !children.is_empty() {
                stack.push((key.to_lowercase(), depth + 1));
                continue;
            }
            outcome.seen += 1;
            let Some((backing, declared)) = volume.wof_backing(entry.record) else { continue };
            if !backing.is_file_provider() {
                continue;
            }
            if !options.any_algorithm && backing.algorithm != wof::ALGORITHM_LZX {
                continue;
            }
            if declared == 0 || declared > MAX_SAMPLE_BYTES {
                continue;
            }

            let cap = declared + declared / 8 + 64 * 1024;
            let stream =
                match volume.fs().read_data_by_record(entry.record, Some(wof::STREAM_NAME), cap) {
                    Ok(stream) if !stream.is_empty() => stream,
                    _ => {
                        outcome.refused_no_stream += 1;
                        continue;
                    }
                };

            let mounted = format!("{}{}", options.mount.trim_end_matches(['\\', '/']), key);
            let plain = match std::fs::read(&mounted) {
                Ok(plain) => plain,
                Err(_) => continue,
            };

            if plain.len() as u64 != declared {
                outcome.refused_wrong_length += 1;
                writeln!(
                    out,
                    "  refused {key}: the filter returned {} bytes, the record declares {declared}",
                    plain.len()
                )?;
                continue;
            }
            if plain.iter().all(|b| *b == 0) {
                outcome.refused_zeroes_or_junk += 1;
                writeln!(
                    out,
                    "  refused {key}: the plaintext read back as all zeroes, which is what the \
                     SPARSE $DATA looks like — the WOF filter is not attached to {}",
                    options.mount
                )?;
                continue;
            }
            let lower = key.to_lowercase();
            if [".exe", ".dll", ".sys"].iter().any(|e| lower.ends_with(e))
                && !plain.starts_with(b"MZ")
            {
                outcome.refused_zeroes_or_junk += 1;
                writeln!(out, "  refused {key}: an executable whose plaintext has no MZ")?;
                continue;
            }

            writeln!(
                out,
                "  captured {key}: {} algorithm, {declared} plaintext bytes, {} stream bytes",
                backing.algorithm_name(),
                stream.len()
            )?;
            outcome.samples.push(Sample {
                path: key,
                provider: backing.provider,
                algorithm: backing.algorithm,
                declared,
                stream,
                plain,
            });
        }
    }

    writeln!(out, "\nwalked {} files", outcome.seen)?;
    writeln!(out, "  captured                {}", outcome.samples.len())?;
    writeln!(out, "  refused, no stream      {}", outcome.refused_no_stream)?;
    writeln!(out, "  refused, wrong length   {}", outcome.refused_wrong_length)?;
    writeln!(out, "  refused, zeroes or junk {}", outcome.refused_zeroes_or_junk)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(path: &str, declared: u64, stream: Vec<u8>, plain: Vec<u8>) -> Sample {
        Sample {
            path: path.into(),
            provider: 2,
            algorithm: wof::ALGORITHM_LZX,
            declared,
            stream,
            plain,
        }
    }

    #[test]
    fn a_capture_round_trips() {
        let samples = vec![
            sample("\\windows\\a.dll", 40_000, vec![1, 2, 3, 4, 5], b"MZplaintext".to_vec()),
            sample("\\windows\\b.sys", 7, vec![], vec![0xff; 7]),
        ];
        let bytes = write_capture(&samples);
        assert_eq!(read_capture(&bytes).unwrap(), samples);
    }

    #[test]
    fn a_damaged_capture_is_refused_rather_than_trusted() {
        let bytes = write_capture(&[sample("\\a", 8, vec![9; 4], vec![1; 8])]);
        for cut in 0..bytes.len() {
            assert!(read_capture(&bytes[..cut]).is_none(), "accepted a {cut}-byte prefix");
        }
        assert!(read_capture(b"not a capture at all").is_none());

        let mut lying = bytes.clone();
        let at = 8 + 4 + 4 + 4 + 2 + 4 + 4 + 8;
        lying[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(read_capture(&lying).is_none());

        let mut many = bytes;
        many[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_capture(&many).is_none());
    }

    #[test]
    fn only_a_chunk_size_the_table_supports_is_reported() {
        let mut stream = 60u32.to_le_bytes().to_vec();
        stream.extend_from_slice(&[0u8; 200]);
        let fits = consistent_chunk_sizes(&sample("\\a", 40_000, stream, Vec::new()));
        assert!(fits.contains(&32768), "{fits:?}");
        assert!(!fits.contains(&4096), "{fits:?}");
    }

    #[test]
    fn a_capture_will_not_be_written_onto_the_volume_it_came_from() {
        use std::path::Path;
        assert!(refuses_to_write_onto("D:\\", Path::new("D:\\lzx.mmcap")));
        assert!(refuses_to_write_onto("D:\\", Path::new("d:\\temp\\lzx.mmcap")));
        assert!(refuses_to_write_onto("D:\\", Path::new("D:/temp/lzx.mmcap")));
        assert!(!refuses_to_write_onto("D:\\", Path::new("E:\\lzx.mmcap")));
        assert!(!refuses_to_write_onto("D:\\", Path::new("DD:\\lzx.mmcap")));
        assert!(!refuses_to_write_onto("", Path::new("E:\\lzx.mmcap")));
    }

    #[test]
    fn describe_refuses_bytes_it_does_not_understand() {
        let mut out = Vec::new();
        assert!(!describe(b"rubbish", "X:\\junk", &mut out).unwrap());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("not a capture this build understands"), "{text}");
    }

    #[test]
    fn describe_prints_the_chunk_size_the_bytes_agree_on() {
        let mut stream = 60u32.to_le_bytes().to_vec();
        stream.extend_from_slice(&[0u8; 200]);
        let bytes = write_capture(&[sample("\\windows\\a.dll", 40_000, stream, vec![1; 40_000])]);
        let mut out = Vec::new();
        assert!(describe(&bytes, "X:\\lzx.mmcap", &mut out).unwrap());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 sample(s)"), "{text}");
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("consistent with ALL 1 LZX samples"), "{text}");
    }
}

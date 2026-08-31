use core::ops::Range;

use authenticode::{PeOffsetError, PeOffsets, PeTrait};

const E_LFANEW: usize = 0x3c;
const PE_MAGIC: [u8; 4] = [b'P', b'E', 0, 0];
const COFF_HEADER_SIZE: usize = 20;
const MAGIC_PE32: u16 = 0x010b;
const MAGIC_PE32_PLUS: u16 = 0x020b;
const DATA_DIR_SIZE: usize = 8;
const SECURITY_DIR_INDEX: usize = 4;
const SECTION_HEADER_SIZE: usize = 40;
const CHECK_SUM_OFFSET: usize = 64;
const SIZE_OF_HEADERS_OFFSET: usize = 60;

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let bytes: [u8; 2] = data.get(at..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let bytes: [u8; 4] = data.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

pub struct PeBytes<'a> {
    data: &'a [u8],
    optional_header: usize,
    data_directories: usize,
    number_of_rva_and_sizes: u32,
    section_table: usize,
    number_of_sections: usize,
    size_of_headers: usize,
    hashable_sections: bool,
}

impl<'a> PeBytes<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.get(..2)? != b"MZ" {
            return None;
        }

        let nt_headers = read_u32(data, E_LFANEW)? as usize;
        if data.get(nt_headers..nt_headers.checked_add(4)?)? != PE_MAGIC {
            return None;
        }

        let coff = nt_headers.checked_add(4)?;
        let number_of_sections = usize::from(read_u16(data, coff.checked_add(2)?)?);
        let size_of_optional_header = usize::from(read_u16(data, coff.checked_add(16)?)?);

        let optional_header = coff.checked_add(COFF_HEADER_SIZE)?;
        let magic = read_u16(data, optional_header)?;

        let (fixed_size, num_rva_offset) = match magic {
            MAGIC_PE32 => (96usize, 92usize),
            MAGIC_PE32_PLUS => (112usize, 108usize),
            _ => return None,
        };

        let number_of_rva_and_sizes = read_u32(data, optional_header.checked_add(num_rva_offset)?)?;
        let data_directories = optional_header.checked_add(fixed_size)?;
        let size_of_headers =
            read_u32(data, optional_header.checked_add(SIZE_OF_HEADERS_OFFSET)?)? as usize;

        let section_table = optional_header.checked_add(size_of_optional_header)?;

        let table_bytes = number_of_sections.checked_mul(SECTION_HEADER_SIZE)?;
        let table_end = section_table.checked_add(table_bytes)?;
        if table_end > data.len() {
            return None;
        }

        if size_of_headers > data.len() {
            return None;
        }

        let mut hashable_sections = true;
        let mut total = size_of_headers;
        for index in 0..number_of_sections {
            let Some(header) = index
                .checked_mul(SECTION_HEADER_SIZE)
                .and_then(|off| section_table.checked_add(off))
            else {
                hashable_sections = false;
                break;
            };
            let (Some(size), Some(start)) = (
                read_u32(data, header.checked_add(16)?).map(|v| v as usize),
                read_u32(data, header.checked_add(20)?).map(|v| v as usize),
            ) else {
                hashable_sections = false;
                break;
            };
            let fits = start.checked_add(size).is_some_and(|end| end <= data.len());
            let Some(sum) = total.checked_add(size).filter(|sum| *sum <= data.len()) else {
                hashable_sections = false;
                break;
            };
            if !fits {
                hashable_sections = false;
                break;
            }
            total = sum;
        }

        Some(PeBytes {
            data,
            optional_header,
            data_directories,
            number_of_rva_and_sizes,
            section_table,
            number_of_sections,
            size_of_headers,
            hashable_sections,
        })
    }

    pub fn sections_fit(&self) -> bool {
        self.hashable_sections
    }

    fn security_data_dir(&self) -> Option<usize> {
        if (self.number_of_rva_and_sizes as usize) <= SECURITY_DIR_INDEX {
            return None;
        }
        self.data_directories.checked_add(SECURITY_DIR_INDEX.checked_mul(DATA_DIR_SIZE)?)
    }
}

impl PeTrait for PeBytes<'_> {
    fn data(&self) -> &[u8] {
        self.data
    }

    fn num_sections(&self) -> usize {
        self.number_of_sections
    }

    fn section_data_range(&self, index: usize) -> Result<Range<usize>, PeOffsetError> {
        if !self.hashable_sections {
            return Err(PeOffsetError);
        }
        let zero_based = index.checked_sub(1).ok_or(PeOffsetError)?;
        if zero_based >= self.number_of_sections {
            return Err(PeOffsetError);
        }
        let header = zero_based
            .checked_mul(SECTION_HEADER_SIZE)
            .and_then(|off| self.section_table.checked_add(off))
            .ok_or(PeOffsetError)?;

        let size = read_u32(self.data, header.checked_add(16).ok_or(PeOffsetError)?)
            .ok_or(PeOffsetError)? as usize;
        let start = read_u32(self.data, header.checked_add(20).ok_or(PeOffsetError)?)
            .ok_or(PeOffsetError)? as usize;
        let end = start.checked_add(size).ok_or(PeOffsetError)?;
        Ok(start..end)
    }

    fn certificate_table_range(&self) -> Result<Option<Range<usize>>, PeOffsetError> {
        let Some(dir) = self.security_data_dir() else {
            return Ok(None);
        };
        let Some(offset) = read_u32(self.data, dir) else {
            return Ok(None);
        };
        let Some(size) = read_u32(self.data, dir.checked_add(4).ok_or(PeOffsetError)?) else {
            return Ok(None);
        };
        if size == 0 {
            return Ok(None);
        }
        let start = offset as usize;
        let end = start.checked_add(size as usize).ok_or(PeOffsetError)?;

        if end > self.data.len() || start > end {
            return Ok(None);
        }

        Ok(Some(start..end))
    }

    fn offsets(&self) -> Result<PeOffsets, PeOffsetError> {
        let check_sum = self.optional_header.checked_add(CHECK_SUM_OFFSET).ok_or(PeOffsetError)?;
        let after_check_sum = check_sum.checked_add(4).ok_or(PeOffsetError)?;

        let security_data_dir = self.security_data_dir().unwrap_or(after_check_sum);
        let after_security_data_dir = if self.security_data_dir().is_some() {
            security_data_dir.checked_add(DATA_DIR_SIZE).ok_or(PeOffsetError)?
        } else {
            security_data_dir
        };

        Ok(PeOffsets {
            check_sum,
            after_check_sum,
            security_data_dir,
            after_security_data_dir,
            after_header: self.size_of_headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_rejected_without_panicking() {
        assert!(PeBytes::parse(&[]).is_none());
        assert!(PeBytes::parse(b"MZ").is_none());
        assert!(PeBytes::parse(b"not a pe file at all").is_none());

        let mut state = 0xdead_beefu32;
        for _ in 0..5_000 {
            let len = (state % 512) as usize;
            let mut buf = vec![b'M', b'Z'];
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            if let Some(pe) = PeBytes::parse(&buf) {
                let _ = pe.offsets();
                let _ = pe.certificate_table_range();
                for i in 0..=pe.num_sections() {
                    let _ = pe.section_data_range(i);
                }
            }
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        }
    }

    #[test]
    fn a_declared_section_count_that_is_not_backed_by_bytes_is_rejected() {
        let mut buf = vec![0u8; 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[E_LFANEW..E_LFANEW + 4].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(&PE_MAGIC);
        buf[0x86..0x88].copy_from_slice(&0xffffu16.to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        buf[0x98..0x9a].copy_from_slice(&MAGIC_PE32_PLUS.to_le_bytes());
        assert!(PeBytes::parse(&buf).is_none());
    }
}

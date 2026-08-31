pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

pub const MAX_NAME_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub tag: u32,
    pub substitute: String,
    pub print: String,
    pub relative: bool,
}

impl Link {
    #[must_use]
    pub fn names_a_volume(&self) -> bool {
        let lower = self.substitute.to_ascii_lowercase();
        let rest = lower
            .strip_prefix("\\??\\")
            .or_else(|| lower.strip_prefix("\\\\?\\"))
            .unwrap_or(&lower);
        rest.starts_with("volume{")
    }

    #[must_use]
    pub fn names_a_remote_share(&self) -> bool {
        let lower = self.substitute.to_ascii_lowercase();
        lower.starts_with("\\??\\unc\\")
            || lower.starts_with("\\\\") && !lower.starts_with("\\\\?\\")
    }
}

#[must_use]
pub fn tag_of(content: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(content.get(0..4)?.try_into().ok()?))
}

#[must_use]
pub fn is_link_tag(tag: u32) -> bool {
    tag == IO_REPARSE_TAG_MOUNT_POINT || tag == IO_REPARSE_TAG_SYMLINK
}

#[must_use]
pub fn parse(content: &[u8]) -> Option<Link> {
    let tag = tag_of(content)?;
    if !is_link_tag(tag) {
        return None;
    }
    let declared = u16::from_le_bytes(content.get(4..6)?.try_into().ok()?) as usize;
    let data = content.get(8..8usize.checked_add(declared)?)?;

    let read16 = |at: usize| -> Option<usize> {
        Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?) as usize)
    };
    let substitute_offset = read16(0)?;
    let substitute_length = read16(2)?;
    let print_offset = read16(4)?;
    let print_length = read16(6)?;

    let (relative, buffer_at) = if tag == IO_REPARSE_TAG_SYMLINK {
        let flags = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?);
        (flags & SYMLINK_FLAG_RELATIVE != 0, 12usize)
    } else {
        (false, 8usize)
    };
    let buffer = data.get(buffer_at..)?;

    let substitute = utf16_at(buffer, substitute_offset, substitute_length)?;
    let print = utf16_at(buffer, print_offset, print_length).unwrap_or_default();

    if substitute.is_empty() {
        return None;
    }
    Some(Link { tag, substitute, print, relative })
}

fn utf16_at(buffer: &[u8], offset: usize, length: usize) -> Option<String> {
    if length == 0 || length > MAX_NAME_BYTES || !length.is_multiple_of(2) {
        return None;
    }
    let end = offset.checked_add(length)?;
    let slice = buffer.get(offset..end)?;
    let units: Vec<u16> = slice.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    Some(char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut out = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(data);
        out
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn mount_point(substitute: &str, print: &str) -> Vec<u8> {
        let sub = utf16(substitute);
        let pr = utf16(print);
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        data.extend_from_slice(&((sub.len() + 2) as u16).to_le_bytes());
        data.extend_from_slice(&(pr.len() as u16).to_le_bytes());
        data.extend_from_slice(&sub);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&pr);
        data.extend_from_slice(&[0, 0]);
        wrap(IO_REPARSE_TAG_MOUNT_POINT, &data)
    }

    fn symlink(substitute: &str, print: &str, flags: u32) -> Vec<u8> {
        let sub = utf16(substitute);
        let pr = utf16(print);
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        data.extend_from_slice(&((sub.len() + 2) as u16).to_le_bytes());
        data.extend_from_slice(&(pr.len() as u16).to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&sub);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&pr);
        data.extend_from_slice(&[0, 0]);
        wrap(IO_REPARSE_TAG_SYMLINK, &data)
    }

    #[test]
    fn a_junction_yields_its_substitute_name() {
        let bytes = mount_point(
            "\\??\\C:\\Program Files\\Common Files\\Oracle\\Java\\javapath_target_2175890",
            "C:\\Program Files\\Common Files\\Oracle\\Java\\javapath_target_2175890",
        );
        let link = parse(&bytes).unwrap();
        assert_eq!(link.tag, IO_REPARSE_TAG_MOUNT_POINT);
        assert!(link.substitute.ends_with("javapath_target_2175890"));
        assert!(link.substitute.starts_with("\\??\\C:\\"));
        assert!(!link.relative);
        assert!(!link.names_a_volume());
    }

    #[test]
    fn the_two_layouts_are_not_interchangeable() {
        let junction = mount_point("\\??\\C:\\target", "C:\\target");
        let as_junction = parse(&junction).unwrap();
        assert_eq!(as_junction.substitute, "\\??\\C:\\target");

        let link = symlink("\\??\\C:\\target", "C:\\target", 0);
        assert_eq!(parse(&link).unwrap().substitute, "\\??\\C:\\target");
    }

    #[test]
    fn a_relative_symlink_says_so() {
        let link = parse(&symlink("..\\sibling", "..\\sibling", SYMLINK_FLAG_RELATIVE)).unwrap();
        assert!(link.relative);
        assert_eq!(link.substitute, "..\\sibling");
    }

    #[test]
    fn a_volume_mount_point_is_recognised_as_naming_a_volume() {
        let link = parse(&mount_point("\\??\\Volume{6b6c9e1a-0000-0000-0000-100000000000}\\", ""))
            .unwrap();
        assert!(link.names_a_volume());
    }

    #[test]
    fn a_wof_reparse_point_is_not_a_link() {
        assert!(parse(&wrap(crate::wof::IO_REPARSE_TAG_WOF, &[0u8; 16])).is_none());
        assert!(parse(&wrap(0x9000_001A, &[0u8; 16])).is_none());
        assert!(parse(&wrap(0x8000_001B, &[0u8; 32])).is_none());
    }

    #[test]
    fn a_truncated_reparse_point_is_refused_at_every_length() {
        let full = mount_point("\\??\\C:\\target", "C:\\target");
        for cut in 0..full.len() {
            assert!(parse(&full[..cut]).is_none(), "a {cut}-byte reparse point must not parse");
        }
        assert!(parse(&full).is_some());
    }

    #[test]
    fn names_that_run_past_the_buffer_are_refused() {
        let mut bytes = mount_point("\\??\\C:\\target", "C:\\target");
        bytes[10] = 0xff;
        bytes[11] = 0x7f;
        assert!(parse(&bytes).is_none());

        let mut bytes = mount_point("\\??\\C:\\target", "C:\\target");
        bytes[8] = 0xf0;
        bytes[9] = 0xff;
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn a_lying_data_length_is_refused() {
        let mut bytes = mount_point("\\??\\C:\\target", "C:\\target");
        bytes[4] = 0xff;
        bytes[5] = 0x0f;
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn an_odd_name_length_is_refused() {
        let mut bytes = mount_point("\\??\\C:\\target", "C:\\target");
        bytes[10] = bytes[10].wrapping_add(1);
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn a_missing_print_name_still_yields_the_link() {
        let bytes = mount_point("\\??\\C:\\target", "");
        let link = parse(&bytes).unwrap();
        assert_eq!(link.substitute, "\\??\\C:\\target");
        assert!(link.print.is_empty());
    }
}

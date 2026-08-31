#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub full: &'a [u8],
    pub content: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn is_constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    pub fn context_tag(&self) -> Option<u8> {
        if self.tag & 0xc0 == 0x80 {
            Some(self.tag & 0x1f)
        } else {
            None
        }
    }

    pub fn children(&self) -> Vec<Tlv<'a>> {
        children(self.content)
    }
}

pub fn read_tlv<'a>(input: &'a [u8], pos: &mut usize) -> Option<Tlv<'a>> {
    let start = *pos;
    let tag = *input.get(start)?;

    if tag & 0x1f == 0x1f {
        return None;
    }

    let len_pos = start.checked_add(1)?;
    let first = *input.get(len_pos)?;

    let (len, header_len) = if first & 0x80 == 0 {
        (usize::from(first), 2usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut value: usize = 0;
        for i in 0..count {
            let byte = *input.get(len_pos.checked_add(1)?.checked_add(i)?)?;
            value = value.checked_mul(256)?.checked_add(usize::from(byte))?;
        }
        (value, count.checked_add(2)?)
    };

    let content_start = start.checked_add(header_len)?;
    let content_end = content_start.checked_add(len)?;
    if content_end > input.len() {
        return None;
    }

    *pos = content_end;
    Some(Tlv {
        tag,
        full: input.get(start..content_end)?,
        content: input.get(content_start..content_end)?,
    })
}

pub fn children(input: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    for_each_child(input, |tlv| out.push(tlv));
    out
}

pub fn for_each_child<'a>(input: &'a [u8], mut visit: impl FnMut(Tlv<'a>)) {
    let mut pos = 0usize;
    while pos < input.len() {
        match read_tlv(input, &mut pos) {
            Some(tlv) => visit(tlv),
            None => break,
        }
    }
}

pub fn single(input: &[u8]) -> Option<Tlv<'_>> {
    let mut pos = 0usize;
    let tlv = read_tlv(input, &mut pos)?;
    if pos == input.len() {
        Some(tlv)
    } else {
        None
    }
}

pub fn first(input: &[u8]) -> Option<Tlv<'_>> {
    let mut pos = 0usize;
    read_tlv(input, &mut pos)
}

pub fn retag_as_set(tlv: &Tlv<'_>) -> Option<Vec<u8>> {
    let mut bytes = tlv.full.to_vec();
    *bytes.first_mut()? = 0x31;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_lengths_are_read() {
        let der = [0x02u8, 0x01, 0x05];
        let tlv = single(&der).unwrap();
        assert_eq!(tlv.tag, 0x02);
        assert_eq!(tlv.content, &[0x05]);
        assert_eq!(tlv.full, &der);
    }

    #[test]
    fn long_form_lengths_are_read() {
        let mut der = vec![0x04u8, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xab, 256));
        let tlv = single(&der).unwrap();
        assert_eq!(tlv.content.len(), 256);
    }

    #[test]
    fn children_walks_a_sequence() {
        let der = [0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let seq = single(&der).unwrap();
        let kids = seq.children();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].content, &[0x01]);
        assert_eq!(kids[1].content, &[0x02]);
    }

    #[test]
    fn truncation_is_never_fatal() {
        for cut in 0..8usize {
            let der = [0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
            assert!(single(&der[..cut]).is_none() || cut == 8);
        }
    }

    #[test]
    fn a_length_past_the_buffer_is_rejected() {
        assert!(single(&[0x04, 0x7f, 0x00]).is_none());
        assert!(single(&[0x04, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn indefinite_and_high_tag_forms_are_rejected() {
        assert!(single(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(single(&[0x1f, 0x81, 0x01, 0x00]).is_none());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x12345678u32;
        for _ in 0..20_000 {
            let len = (state % 64) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            let _ = single(&buf);
            let _ = first(&buf);
            for kid in children(&buf) {
                let _ = kid.children();
                let _ = kid.context_tag();
            }
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        }
    }

    #[test]
    fn retagging_preserves_everything_but_the_tag() {
        let der = [0xa0u8, 0x03, 0x02, 0x01, 0x07];
        let tlv = single(&der).unwrap();
        let set = retag_as_set(&tlv).unwrap();
        assert_eq!(set, vec![0x31, 0x03, 0x02, 0x01, 0x07]);
    }
}

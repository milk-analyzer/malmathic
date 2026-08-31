pub(crate) struct InUse<'a>(pub(crate) &'a [u8]);

impl InUse<'_> {
    pub(crate) fn is_set(&self, buffer: usize) -> bool {
        self.0.get(buffer / 8).is_some_and(|byte| byte & (1 << (buffer % 8)) != 0)
    }

    fn highest_set(&self) -> Option<usize> {
        self.0
            .iter()
            .enumerate()
            .rev()
            .find(|(_, byte)| **byte != 0)
            .map(|(i, byte)| i * 8 + (7 - byte.leading_zeros() as usize))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Incomplete {
    NotAnIndexBuffer(usize),
    NoBitmap(usize),
    PastTheValue { buffer: usize, buffers: usize },
}

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Incomplete::NotAnIndexBuffer(buffer) => write!(
                f,
                "index record {buffer} is in use according to the $I30 $BITMAP and did not read \
                 back as an INDX buffer"
            ),
            Incomplete::NoBitmap(buffer) => write!(
                f,
                "index record {buffer} did not read back as an INDX buffer and the directory has \
                 no readable $I30 $BITMAP to say whether it should have"
            ),
            Incomplete::PastTheValue { buffer, buffers } => write!(
                f,
                "the $I30 $BITMAP says index record {buffer} is in use and only {buffers} were \
                 read"
            ),
        }
    }
}

pub(crate) fn incompleteness(read_back: &[bool], bitmap: Option<InUse>) -> Option<Incomplete> {
    let first_gap = read_back.iter().position(|ok| !ok);

    let Some(bitmap) = bitmap else {
        return first_gap.map(Incomplete::NoBitmap);
    };

    if let Some(highest) = bitmap.highest_set() {
        if highest >= read_back.len() {
            return Some(Incomplete::PastTheValue { buffer: highest, buffers: read_back.len() });
        }
    }

    first_gap?;
    read_back
        .iter()
        .enumerate()
        .find(|(buffer, ok)| !**ok && bitmap.is_set(*buffer))
        .map(|(buffer, _)| Incomplete::NotAnIndexBuffer(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_whose_every_buffer_read_back_is_complete() {
        assert_eq!(incompleteness(&[true, true, true], None), None);
        assert_eq!(incompleteness(&[true, true, true], Some(InUse(&[0b0000_0111]))), None);
    }

    #[test]
    fn a_buffer_the_bitmap_calls_unused_may_be_anything() {
        assert_eq!(incompleteness(&[true, false, true], Some(InUse(&[0b0000_0101]))), None);
    }

    #[test]
    fn a_buffer_the_bitmap_calls_used_must_have_read_back() {
        assert_eq!(
            incompleteness(&[true, false, true], Some(InUse(&[0b0000_0111]))),
            Some(Incomplete::NotAnIndexBuffer(1))
        );
    }

    #[test]
    fn a_gap_with_no_bitmap_is_refused() {
        assert_eq!(incompleteness(&[true, false], None), Some(Incomplete::NoBitmap(1)));
    }

    #[test]
    fn a_bit_past_the_value_is_refused_even_with_no_gap() {
        assert_eq!(
            incompleteness(&[true, true], Some(InUse(&[0b0000_0111]))),
            Some(Incomplete::PastTheValue { buffer: 2, buffers: 2 })
        );
    }

    #[test]
    fn the_bitmap_reads_bits_from_the_bottom_of_each_byte() {
        let bits = [0b1000_0000u8, 0b0000_0001];
        assert!(!InUse(&bits).is_set(0));
        assert!(InUse(&bits).is_set(7));
        assert!(InUse(&bits).is_set(8));
        assert!(!InUse(&bits).is_set(9));
        assert_eq!(InUse(&bits).highest_set(), Some(8));
        assert_eq!(InUse(&[]).highest_set(), None);
        assert_eq!(InUse(&[0, 0]).highest_set(), None);
    }

    #[test]
    fn nothing_to_read_is_not_a_gap() {
        assert_eq!(incompleteness(&[], None), None);
        assert_eq!(incompleteness(&[], Some(InUse(&[0]))), None);
    }
}

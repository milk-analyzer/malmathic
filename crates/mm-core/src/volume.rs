use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize)]
pub enum VolumeRef {
    #[default]
    Unstated,
    Letter(char),
    Device(String),
    Token(String),
}

impl VolumeRef {
    pub fn label(&self) -> String {
        match self {
            VolumeRef::Unstated => "this volume".into(),
            VolumeRef::Letter(c) => format!("{}:", c.to_ascii_uppercase()),
            VolumeRef::Device(d) => format!("\\Device\\{d}"),
            VolumeRef::Token(t) => match token_serial(t) {
                Some(serial) => format!("volume serial {serial:08x}"),
                None => format!("\\\\?\\Volume{{{t}}}"),
            },
        }
    }

    pub fn is_stated(&self) -> bool {
        !matches!(self, VolumeRef::Unstated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeMatch {
    Same,
    Other,
    Unknown,
}

impl VolumeMatch {
    pub fn resolvable_here(&self) -> bool {
        !matches!(self, VolumeMatch::Other)
    }
}

#[derive(Clone, Debug, Default)]
pub struct VolumeIdentity {
    serial: u64,
    system_letter: Option<char>,
    mounted: BTreeMap<char, String>,
}

impl VolumeIdentity {
    pub fn new(serial: u64) -> Self {
        VolumeIdentity { serial, system_letter: None, mounted: BTreeMap::new() }
    }

    pub fn set_system_root(&mut self, system_root: &str) {
        if let Some(letter) = letter_of(system_root) {
            self.system_letter = Some(letter);
        }
    }

    pub fn set_mounted_devices(&mut self, entries: impl IntoIterator<Item = (char, String)>) {
        for (letter, description) in entries {
            if let Some(c) = normalize_letter(letter) {
                self.mounted.insert(c, description);
            }
        }
    }

    #[must_use]
    pub fn with_system_root(mut self, system_root: &str) -> Self {
        self.set_system_root(system_root);
        self
    }

    #[must_use]
    pub fn with_mounted_devices(
        mut self,
        entries: impl IntoIterator<Item = (char, String)>,
    ) -> Self {
        self.set_mounted_devices(entries);
        self
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn system_letter(&self) -> Option<char> {
        self.system_letter
    }

    pub fn mounted_as(&self, letter: char) -> Option<&str> {
        normalize_letter(letter).and_then(|c| self.mounted.get(&c)).map(String::as_str)
    }

    pub fn judge(&self, volume: &VolumeRef) -> VolumeMatch {
        match volume {
            VolumeRef::Unstated => VolumeMatch::Same,
            VolumeRef::Letter(l) => match self.system_letter {
                Some(system) if system == *l => VolumeMatch::Same,
                Some(_) => VolumeMatch::Other,
                None => VolumeMatch::Unknown,
            },
            VolumeRef::Device(_) => VolumeMatch::Unknown,
            VolumeRef::Token(t) => match self.token_match(t) {
                Some(true) => VolumeMatch::Same,
                Some(false) => VolumeMatch::Other,
                None => VolumeMatch::Unknown,
            },
        }
    }

    fn token_match(&self, token: &str) -> Option<bool> {
        if self.serial == 0 {
            return None;
        }
        let token = token_serial(token)?;
        if token == 0 {
            return None;
        }
        Some(u64::from(token) == self.serial & 0xffff_ffff)
    }
}

pub fn token_serial(token: &str) -> Option<u32> {
    let (created, serial) = token.split_once('-')?;
    if created.len() != 16 || serial.len() != 8 {
        return None;
    }
    if !created.bytes().chain(serial.bytes()).all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(serial, 16).ok()
}

fn letter_of(path: &str) -> Option<char> {
    let s = path.trim().trim_matches('"');
    let mut chars = s.chars();
    let first = chars.next()?;
    if chars.next()? != ':' {
        return None;
    }
    normalize_letter(first)
}

fn normalize_letter(c: char) -> Option<char> {
    c.is_ascii_alphabetic().then(|| c.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unstated_volume_is_this_volume() {
        let id = VolumeIdentity::new(1).with_system_root("C:\\WINDOWS");
        assert_eq!(id.judge(&VolumeRef::Unstated), VolumeMatch::Same);
    }

    #[test]
    fn the_systems_own_letter_matches() {
        let id = VolumeIdentity::new(1).with_system_root("C:\\WINDOWS");
        assert_eq!(id.judge(&VolumeRef::Letter('c')), VolumeMatch::Same);
    }

    #[test]
    fn another_letter_is_another_volume() {
        let id = VolumeIdentity::new(1).with_system_root("C:\\WINDOWS");
        assert_eq!(id.judge(&VolumeRef::Letter('w')), VolumeMatch::Other);
        assert!(!id.judge(&VolumeRef::Letter('w')).resolvable_here());
    }

    #[test]
    fn the_letter_winre_assigned_is_not_used() {
        let id = VolumeIdentity::new(1).with_system_root("C:\\Windows");
        assert_eq!(id.judge(&VolumeRef::Letter('c')), VolumeMatch::Same);
        assert_eq!(id.judge(&VolumeRef::Letter('d')), VolumeMatch::Other);
    }

    #[test]
    fn without_a_system_root_nothing_is_decided() {
        let id = VolumeIdentity::new(1);
        assert_eq!(id.judge(&VolumeRef::Letter('w')), VolumeMatch::Unknown);
        assert!(id.judge(&VolumeRef::Letter('w')).resolvable_here());
        assert_eq!(id.judge(&VolumeRef::Unstated), VolumeMatch::Same);
    }

    #[test]
    fn device_and_serialless_token_volumes_are_undecided_and_so_unchanged() {
        let id = VolumeIdentity::new(1).with_system_root("C:\\WINDOWS");
        assert_eq!(id.judge(&VolumeRef::Device("harddiskvolume3".into())), VolumeMatch::Unknown);
        assert_eq!(id.judge(&VolumeRef::Token("01d7a1".into())), VolumeMatch::Unknown);
        assert!(id.judge(&VolumeRef::Device("harddiskvolume3".into())).resolvable_here());
    }

    #[test]
    fn a_prefetch_token_whose_serial_matches_is_this_volume() {
        let id = VolumeIdentity::new(0x7a6b_5c4d_3e2f_1009).with_system_root("C:\\WINDOWS");
        let token = VolumeRef::Token("01dcde9988776655-3e2f1009".into());
        assert_eq!(id.judge(&token), VolumeMatch::Same);
        assert!(id.judge(&token).resolvable_here());
    }

    #[test]
    fn a_prefetch_token_whose_serial_differs_is_another_volume() {
        let id = VolumeIdentity::new(0x7a6b_5c4d_3e2f_1009).with_system_root("C:\\WINDOWS");
        let cdrom = VolumeRef::Token("0000000000000000-6d5c4b3a".into());
        assert_eq!(id.judge(&cdrom), VolumeMatch::Other);
        assert!(!id.judge(&cdrom).resolvable_here());
    }

    #[test]
    fn a_guid_token_carries_no_serial_and_stays_undecided() {
        let id = VolumeIdentity::new(0x7a6b_5c4d_3e2f_1009).with_system_root("C:\\WINDOWS");
        for guid in [
            "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa",
            "2c3d4e5f-0000-0000-0000-300300000000",
            "0b1c2d3e-4f50-6172",
            "3e2f1009-0884-53dd-0884-3e2f10090884",
        ] {
            assert_eq!(
                id.judge(&VolumeRef::Token(guid.into())),
                VolumeMatch::Unknown,
                "guid: {guid}"
            );
            assert!(id.judge(&VolumeRef::Token(guid.into())).resolvable_here());
        }
    }

    #[test]
    fn only_the_two_group_hex_pair_is_read_as_a_serial() {
        assert_eq!(token_serial("01dcde9988776655-3e2f1009"), Some(0x3e2f_1009));
        assert_eq!(token_serial("0000000000000000-6d5c4b3a"), Some(0x6d5c_4b3a));
        assert_eq!(token_serial("01d7a1b2c3d4e5f6"), None);
        assert_eq!(token_serial("01dcde998877665-3e2f1009"), None);
        assert_eq!(token_serial("01dcde9988776655-3e2f100"), None);
        assert_eq!(token_serial("01dcde9988776655-3e2f1009-1009"), None);
        assert_eq!(token_serial("01dcde9988776655-+3e2f100"), None);
        assert_eq!(token_serial("01dcde99887766zz-3e2f1009"), None);
        assert_eq!(token_serial(""), None);
        assert_eq!(token_serial("-"), None);
    }

    #[test]
    fn without_a_serial_no_token_is_judged() {
        let id = VolumeIdentity::default().with_system_root("C:\\WINDOWS");
        let token = VolumeRef::Token("01dcde9988776655-3e2f1009".into());
        assert_eq!(id.judge(&token), VolumeMatch::Unknown);
        assert!(id.judge(&token).resolvable_here());

        let known = VolumeIdentity::new(0x7a6b_5c4d_3e2f_1009);
        assert_eq!(
            known.judge(&VolumeRef::Token("01dcde9988776655-00000000".into())),
            VolumeMatch::Unknown
        );
    }

    #[test]
    fn only_the_low_thirty_two_bits_are_compared() {
        let id = VolumeIdentity::new(0x5f4e_3d2c_1b0a_9988);
        assert_eq!(
            id.judge(&VolumeRef::Token("01dcee1122334455-1b0a9988".into())),
            VolumeMatch::Same
        );
        assert_eq!(
            id.judge(&VolumeRef::Token("01dcee1122334455-5f4e3d2c".into())),
            VolumeMatch::Other
        );
    }

    #[test]
    fn a_system_root_that_is_not_a_letter_path_is_not_guessed_at() {
        let id = VolumeIdentity::new(1).with_system_root("\\SystemRoot");
        assert_eq!(id.system_letter(), None);
        assert_eq!(id.judge(&VolumeRef::Letter('w')), VolumeMatch::Unknown);
    }

    #[test]
    fn mounted_devices_are_a_lead_not_a_verdict() {
        let id = VolumeIdentity::new(1)
            .with_system_root("C:\\WINDOWS")
            .with_mounted_devices([('W', "disk signature 0x1a2b3c4d at offset 0x100000".into())]);
        assert_eq!(id.mounted_as('w').unwrap(), "disk signature 0x1a2b3c4d at offset 0x100000");
        assert_eq!(id.mounted_as('z'), None);
        assert_eq!(id.judge(&VolumeRef::Letter('w')), VolumeMatch::Other);
    }

    #[test]
    fn labels_read_the_way_an_analyst_writes_them() {
        assert_eq!(VolumeRef::Letter('w').label(), "W:");
        assert_eq!(
            VolumeRef::Device("harddiskvolume3".into()).label(),
            "\\Device\\harddiskvolume3"
        );
        assert_eq!(VolumeRef::Token("abc".into()).label(), "\\\\?\\Volume{abc}");
        assert_eq!(
            VolumeRef::Token("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa".into()).label(),
            "\\\\?\\Volume{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa}"
        );
        assert_eq!(
            VolumeRef::Token("0000000000000000-6d5c4b3a".into()).label(),
            "volume serial 6d5c4b3a"
        );
        assert_eq!(VolumeRef::Unstated.label(), "this volume");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeKind {
    Ntfs,
    BitLocker,
    Fat,
    ExFat,
    ReFs,
    Unknown,
}

impl VolumeKind {
    pub fn label(&self) -> &'static str {
        match self {
            VolumeKind::Ntfs => "NTFS",
            VolumeKind::BitLocker => "BitLocker (locked)",
            VolumeKind::Fat => "FAT",
            VolumeKind::ExFat => "exFAT",
            VolumeKind::ReFs => "ReFS",
            VolumeKind::Unknown => "unrecognized",
        }
    }
}

pub fn classify(sector: &[u8]) -> VolumeKind {
    if sector.len() < 11 {
        return VolumeKind::Unknown;
    }
    match &sector[3..11] {
        b"NTFS    " => VolumeKind::Ntfs,
        b"-FVE-FS-" => VolumeKind::BitLocker,
        b"EXFAT   " => VolumeKind::ExFat,
        b"ReFS\0\0\0\0" => VolumeKind::ReFs,
        _ => classify_fat(sector),
    }
}

fn classify_fat(sector: &[u8]) -> VolumeKind {
    let fat1x = sector.len() >= 62 && matches!(&sector[54..59], b"FAT12" | b"FAT16" | b"FAT  ");
    let fat32 = sector.len() >= 90 && &sector[82..87] == b"FAT32";
    if fat1x || fat32 {
        VolumeKind::Fat
    } else {
        VolumeKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sector_with_oem(oem: &[u8; 8]) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[3..11].copy_from_slice(oem);
        s
    }

    #[test]
    fn ntfs_is_recognized() {
        assert_eq!(classify(&sector_with_oem(b"NTFS    ")), VolumeKind::Ntfs);
    }

    #[test]
    fn locked_bitlocker_is_recognized_not_mistaken_for_junk() {
        assert_eq!(classify(&sector_with_oem(b"-FVE-FS-")), VolumeKind::BitLocker);
    }

    #[test]
    fn exfat_and_refs_are_recognized() {
        assert_eq!(classify(&sector_with_oem(b"EXFAT   ")), VolumeKind::ExFat);
        assert_eq!(classify(&sector_with_oem(b"ReFS\0\0\0\0")), VolumeKind::ReFs);
    }

    #[test]
    fn fat_is_detected_by_type_field_not_oem_string() {
        let mut s = sector_with_oem(b"NONSENSE");
        s[54..59].copy_from_slice(b"FAT16");
        assert_eq!(classify(&s), VolumeKind::Fat);

        let mut s = sector_with_oem(b"MSDOS5.0");
        s[82..87].copy_from_slice(b"FAT32");
        assert_eq!(classify(&s), VolumeKind::Fat);
    }

    #[test]
    fn short_and_empty_sectors_are_unknown_not_panics() {
        assert_eq!(classify(&[]), VolumeKind::Unknown);
        assert_eq!(classify(&[0u8; 3]), VolumeKind::Unknown);
        assert_eq!(classify(&[0u8; 10]), VolumeKind::Unknown);
        assert_eq!(classify(&vec![0u8; 512]), VolumeKind::Unknown);
    }
}

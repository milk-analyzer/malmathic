use chrono::{DateTime, Utc};

use crate::{FileHash, NormalizedPath};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ArtifactSource {
    Mft,
    UsnJournal,
    Amcache,
    ShimCache,
    Prefetch,
    Srum,
    UserAssist,
    BamDam,
    Pca,
    Registry { hive: String, key: String },
    ScheduledTask { file: String },
    StartupFolder { file: String },
    EventLog { channel: String, event_id: u32 },
    DefenderQuarantine,
    DefenderLog { event_id: u32 },
    RecycleBin,
    UnallocatedClusters,
    VolumeShadowCopy { snapshot: String },
    WerDump,
    ZoneIdentifier,
    LiveProcess { pid: u32 },
    FileContent,
}

impl ArtifactSource {
    pub fn label(&self) -> String {
        match self {
            ArtifactSource::Mft => "$MFT".into(),
            ArtifactSource::UsnJournal => "USN journal".into(),
            ArtifactSource::Amcache => "Amcache".into(),
            ArtifactSource::ShimCache => "ShimCache".into(),
            ArtifactSource::Prefetch => "Prefetch".into(),
            ArtifactSource::Srum => "SRUM".into(),
            ArtifactSource::UserAssist => "UserAssist".into(),
            ArtifactSource::BamDam => "BAM/DAM".into(),
            ArtifactSource::Pca => "PCA".into(),
            ArtifactSource::Registry { hive, key } => format!("{hive}\\{key}"),
            ArtifactSource::ScheduledTask { file } => format!("task {file}"),
            ArtifactSource::StartupFolder { file } => format!("startup {file}"),
            ArtifactSource::EventLog { channel, event_id } => format!("{channel} #{event_id}"),
            ArtifactSource::DefenderQuarantine => "Defender quarantine".into(),
            ArtifactSource::DefenderLog { event_id } => format!("Defender log #{event_id}"),
            ArtifactSource::RecycleBin => "$Recycle.Bin".into(),
            ArtifactSource::UnallocatedClusters => "unallocated clusters".into(),
            ArtifactSource::VolumeShadowCopy { snapshot } => format!("VSS {snapshot}"),
            ArtifactSource::WerDump => "WER dump".into(),
            ArtifactSource::ZoneIdentifier => "Zone.Identifier".into(),
            ArtifactSource::LiveProcess { pid } => format!("live pid {pid}"),
            ArtifactSource::FileContent => "file content".into(),
        }
    }

    pub fn family(&self) -> &'static str {
        match self {
            ArtifactSource::Mft
            | ArtifactSource::UsnJournal
            | ArtifactSource::ZoneIdentifier
            | ArtifactSource::UnallocatedClusters => "filesystem",
            ArtifactSource::Amcache
            | ArtifactSource::ShimCache
            | ArtifactSource::Prefetch
            | ArtifactSource::Srum
            | ArtifactSource::UserAssist
            | ArtifactSource::BamDam
            | ArtifactSource::Pca => "execution",
            ArtifactSource::Registry { .. }
            | ArtifactSource::ScheduledTask { .. }
            | ArtifactSource::StartupFolder { .. } => "persistence",
            ArtifactSource::EventLog { .. } => "eventlog",
            ArtifactSource::DefenderQuarantine | ArtifactSource::DefenderLog { .. } => "antivirus",
            ArtifactSource::RecycleBin
            | ArtifactSource::VolumeShadowCopy { .. }
            | ArtifactSource::WerDump => "recovery",
            ArtifactSource::LiveProcess { .. } => "runtime",
            ArtifactSource::FileContent => "content",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PersistenceKind {
    RunKey,
    RunOnceKey,
    StartupFolder,
    Service,
    ScheduledTask,
    WinlogonShell,
    WinlogonUserinit,
    ImageFileExecutionOptions,
    AppInitDlls,
    ComServer,
    ComHijack,
    WmiSubscription,
    BootExecute,
    LsaProvider,
    ScreenSaver,
}

impl PersistenceKind {
    pub fn attack_id(&self) -> &'static str {
        match self {
            PersistenceKind::RunKey | PersistenceKind::RunOnceKey => "T1547.001",
            PersistenceKind::StartupFolder => "T1547.001",
            PersistenceKind::Service => "T1543.003",
            PersistenceKind::ScheduledTask => "T1053.005",
            PersistenceKind::WinlogonShell | PersistenceKind::WinlogonUserinit => "T1547.004",
            PersistenceKind::ImageFileExecutionOptions => "T1546.012",
            PersistenceKind::AppInitDlls => "T1546.010",
            PersistenceKind::ComServer | PersistenceKind::ComHijack => "T1546.015",
            PersistenceKind::WmiSubscription => "T1546.003",
            PersistenceKind::BootExecute => "T1547.001",
            PersistenceKind::LsaProvider => "T1547.005",
            PersistenceKind::ScreenSaver => "T1546.002",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            PersistenceKind::RunKey => "Run key",
            PersistenceKind::RunOnceKey => "RunOnce key",
            PersistenceKind::StartupFolder => "Startup folder",
            PersistenceKind::Service => "service",
            PersistenceKind::ScheduledTask => "scheduled task",
            PersistenceKind::WinlogonShell => "Winlogon Shell",
            PersistenceKind::WinlogonUserinit => "Winlogon Userinit",
            PersistenceKind::ImageFileExecutionOptions => "IFEO debugger",
            PersistenceKind::AppInitDlls => "AppInit_DLLs",
            PersistenceKind::ComServer => "COM server registration",
            PersistenceKind::ComHijack => "COM hijack",
            PersistenceKind::WmiSubscription => "WMI subscription",
            PersistenceKind::BootExecute => "BootExecute",
            PersistenceKind::LsaProvider => "LSA provider",
            PersistenceKind::ScreenSaver => "screensaver",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureStatus {
    Unsigned,
    EmbeddedValid {
        signer: String,
    },
    CatalogValid {
        signer: String,
        catalog: String,
        root_is_microsoft: bool,
    },
    Invalid {
        reason: String,
    },
    Untrusted {
        signer: String,
        #[serde(default)]
        self_signed_leaf: bool,
    },
    Expired {
        signer: String,
    },
    Unknown {
        reason: String,
    },
}

impl SignatureStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureStatus::EmbeddedValid { .. } | SignatureStatus::CatalogValid { .. })
    }

    pub fn is_evidence(&self) -> bool {
        !matches!(self, SignatureStatus::Unknown { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutOfBandArrival {
    NotAComponentStoreLink { hard_links: u16 },
    AfterItsDirectory { days_later: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UrlZone {
    LocalMachine,
    LocalIntranet,
    Trusted,
    Internet,
    Untrusted,
    Other(u32),
    Unstated,
}

impl UrlZone {
    pub fn from_id(id: u32) -> Self {
        match id {
            0 => UrlZone::LocalMachine,
            1 => UrlZone::LocalIntranet,
            2 => UrlZone::Trusted,
            3 => UrlZone::Internet,
            4 => UrlZone::Untrusted,
            other => UrlZone::Other(other),
        }
    }

    pub fn label(&self) -> String {
        match self {
            UrlZone::LocalMachine => "local machine".into(),
            UrlZone::LocalIntranet => "local intranet".into(),
            UrlZone::Trusted => "trusted sites".into(),
            UrlZone::Internet => "internet".into(),
            UrlZone::Untrusted => "restricted sites".into(),
            UrlZone::Other(id) => format!("unrecognised zone {id}"),
            UrlZone::Unstated => "unstated".into(),
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, UrlZone::Internet | UrlZone::Untrusted)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ObservationKind {
    FileExists {
        size: u64,
        created: Option<DateTime<Utc>>,
        modified: Option<DateTime<Utc>>,
        mft_modified: Option<DateTime<Utc>>,
        #[serde(default)]
        record: Option<u64>,
    },
    FileDeleted {
        when: Option<DateTime<Utc>>,
        record: Option<u64>,
        #[serde(default)]
        sequence: Option<u16>,
    },
    DeletedRegistryValue {
        value_name: String,
        raw_value: String,
    },
    Executed {
        when: Option<DateTime<Utc>>,
        run_count: Option<u32>,
    },
    Persistence {
        kind: PersistenceKind,
        raw_value: String,
    },
    DownloadedFrom {
        zone: UrlZone,
        host_url: Option<String>,
        referrer_url: Option<String>,
    },
    HashRecovered,
    Signature(SignatureStatus),
    ManagedAssembly,
    Quarantined {
        product: String,
        threat: Option<String>,
        #[serde(default)]
        when: Option<DateTime<Utc>>,
        #[serde(default)]
        severity: Option<u32>,
    },
    AvDetected {
        product: String,
        threat: Option<String>,
        #[serde(default)]
        when: Option<DateTime<Utc>>,
        #[serde(default)]
        severity: Option<u32>,
    },
    ArrivedOutOfBand(OutOfBandArrival),
    CompactOsCompressed {
        algorithm: String,
        readable: bool,
    },
    NoVersionResource,
    SharedDigestElsewhere {
        path: NormalizedPath,
        algorithm: String,
        copies: u32,
    },
    YaraMatch {
        rule: String,
        namespace: String,
    },
    PeAnomaly {
        detail: String,
    },
    RichHeaderChecksumInvalid {
        entries: usize,
        decoded: bool,
    },
    ProcessRunning {
        pid: u32,
        parent_pid: Option<u32>,
        command_line: Option<String>,
    },
    UnbackedExecutableMemory {
        pid: u32,
        size: u64,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    pub source: ArtifactSource,
    pub kind: ObservationKind,
    pub path: Option<NormalizedPath>,
    pub hash: FileHash,
}

impl Observation {
    pub fn about_path(source: ArtifactSource, path: NormalizedPath, kind: ObservationKind) -> Self {
        Observation { source, kind, path: Some(path), hash: FileHash::default() }
    }

    pub fn about_hash(source: ArtifactSource, hash: FileHash, kind: ObservationKind) -> Self {
        Observation { source, kind, path: None, hash }
    }

    pub fn with_hash(mut self, hash: FileHash) -> Self {
        self.hash.merge(&hash);
        self
    }

    pub fn identifies_something(&self) -> bool {
        self.path.is_some() || !self.hash.is_empty()
    }

    pub fn timestamp(&self) -> Option<DateTime<Utc>> {
        match &self.kind {
            ObservationKind::FileExists { created, modified, .. } => created.or(*modified),
            ObservationKind::FileDeleted { when, .. } => *when,
            ObservationKind::Executed { when, .. } => *when,
            ObservationKind::Quarantined { when, .. } => *when,
            ObservationKind::AvDetected { when, .. } => *when,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    #[test]
    fn independent_families_are_distinguished() {
        assert_eq!(ArtifactSource::Amcache.family(), ArtifactSource::Prefetch.family());
        assert_eq!(ArtifactSource::Mft.family(), ArtifactSource::UsnJournal.family());
        assert_ne!(ArtifactSource::Amcache.family(), ArtifactSource::Mft.family());
        assert_ne!(
            ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "Run".into() }.family(),
            ArtifactSource::Amcache.family()
        );
    }

    #[test]
    fn only_real_signatures_exonerate() {
        assert!(SignatureStatus::EmbeddedValid { signer: "MS".into() }.is_trusted());
        assert!(SignatureStatus::CatalogValid {
            signer: "MS".into(),
            catalog: "a.cat".into(),
            root_is_microsoft: true
        }
        .is_trusted());
        assert!(!SignatureStatus::Unsigned.is_trusted());
        assert!(!SignatureStatus::Untrusted { signer: "evil".into(), self_signed_leaf: true }
            .is_trusted());
        assert!(!SignatureStatus::Invalid { reason: "bad".into() }.is_trusted());
        assert!(!SignatureStatus::Expired { signer: "old".into() }.is_trusted());
        assert!(!SignatureStatus::Unknown { reason: "no CatRoot".into() }.is_trusted());
    }

    #[test]
    fn a_check_that_did_not_run_is_not_evidence() {
        assert!(!SignatureStatus::Unknown { reason: "CatRoot unreadable".into() }.is_evidence());
        assert!(SignatureStatus::Unsigned.is_evidence());
        assert!(SignatureStatus::Invalid { reason: "hash mismatch".into() }.is_evidence());
        assert!(SignatureStatus::EmbeddedValid { signer: "MS".into() }.is_evidence());
    }

    #[test]
    fn a_catalog_says_whether_its_root_is_microsoft() {
        let oem = SignatureStatus::CatalogValid {
            signer: "OpenVPN Technologies, Inc.".into(),
            catalog: "oem40.cat".into(),
            root_is_microsoft: false,
        };
        let ms = SignatureStatus::CatalogValid {
            signer: "Microsoft Windows".into(),
            catalog: "Package_1.cat".into(),
            root_is_microsoft: true,
        };
        assert!(oem.is_trusted() && ms.is_trusted());
        assert_ne!(oem, ms);
    }

    #[test]
    fn observations_must_identify_a_file() {
        let o = Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\x.exe"),
            ObservationKind::HashRecovered,
        );
        assert!(o.identifies_something());

        let o = Observation::about_hash(
            ArtifactSource::DefenderLog { event_id: 1117 },
            FileHash::compute(b"x"),
            ObservationKind::HashRecovered,
        );
        assert!(o.identifies_something());

        let empty = Observation {
            source: ArtifactSource::Mft,
            kind: ObservationKind::HashRecovered,
            path: None,
            hash: FileHash::default(),
        };
        assert!(!empty.identifies_something());
    }

    #[test]
    fn url_zones_map_from_their_wire_ids() {
        assert_eq!(UrlZone::from_id(0), UrlZone::LocalMachine);
        assert_eq!(UrlZone::from_id(3), UrlZone::Internet);
        assert_eq!(UrlZone::from_id(4), UrlZone::Untrusted);
        assert_eq!(UrlZone::from_id(9), UrlZone::Other(9));
        assert_eq!(UrlZone::from_id(u32::MAX), UrlZone::Other(u32::MAX));
    }

    #[test]
    fn an_unstated_zone_is_not_a_claim_in_either_direction() {
        assert!(!UrlZone::Unstated.is_remote());
        assert!(!UrlZone::LocalMachine.is_remote());
        assert_ne!(UrlZone::Unstated, UrlZone::LocalMachine);
        assert!(UrlZone::Internet.is_remote());
        assert!(UrlZone::Untrusted.is_remote());
        for zone in [
            UrlZone::LocalMachine,
            UrlZone::Internet,
            UrlZone::Untrusted,
            UrlZone::Other(7),
            UrlZone::Unstated,
        ] {
            assert!(!zone.label().is_empty());
        }
        assert!(UrlZone::Other(7).label().contains('7'));
    }

    #[test]
    fn one_av_products_two_records_are_one_family() {
        assert_eq!(
            ArtifactSource::DefenderLog { event_id: 1117 }.family(),
            ArtifactSource::DefenderQuarantine.family()
        );
        assert_ne!(
            ArtifactSource::DefenderLog { event_id: 1116 }.family(),
            ArtifactSource::EventLog { channel: "Security".into(), event_id: 4688 }.family()
        );
        assert_eq!(ArtifactSource::DefenderLog { event_id: 1118 }.label(), "Defender log #1118");
    }

    #[test]
    fn an_av_detection_time_is_a_moment_the_window_can_anchor_on() {
        let when = DateTime::from_timestamp(1_785_272_874, 0).unwrap();
        for kind in [
            ObservationKind::AvDetected {
                product: "Windows Defender".into(),
                threat: None,
                when: Some(when),
                severity: None,
            },
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: None,
                when: Some(when),
                severity: None,
            },
        ] {
            let o = Observation::about_path(
                ArtifactSource::DefenderLog { event_id: 1117 },
                path("C:\\x.exe"),
                kind,
            );
            assert_eq!(o.timestamp(), Some(when));
        }

        let unknown = Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1116 },
            path("C:\\x.exe"),
            ObservationKind::AvDetected {
                product: "Windows Defender".into(),
                threat: None,
                when: None,
                severity: None,
            },
        );
        assert!(unknown.timestamp().is_none());
    }

    #[test]
    fn mark_of_the_web_does_not_count_as_its_own_family() {
        assert_eq!(ArtifactSource::ZoneIdentifier.family(), ArtifactSource::Mft.family());
        assert_eq!(ArtifactSource::ZoneIdentifier.label(), "Zone.Identifier");
    }

    #[test]
    fn persistence_carries_attack_mapping() {
        assert_eq!(PersistenceKind::RunKey.attack_id(), "T1547.001");
        assert_eq!(PersistenceKind::ScheduledTask.attack_id(), "T1053.005");
        assert_eq!(PersistenceKind::ImageFileExecutionOptions.attack_id(), "T1546.012");
    }

    #[test]
    fn timestamps_surface_from_the_kinds_that_have_them() {
        let when = DateTime::from_timestamp(1_704_067_200, 0).unwrap();
        let o = Observation::about_path(
            ArtifactSource::Prefetch,
            path("C:\\x.exe"),
            ObservationKind::Executed { when: Some(when), run_count: Some(3) },
        );
        assert_eq!(o.timestamp(), Some(when));

        let o = Observation::about_path(
            ArtifactSource::FileContent,
            path("C:\\x.exe"),
            ObservationKind::YaraMatch { rule: "r".into(), namespace: "n".into() },
        );
        assert!(o.timestamp().is_none());
    }
}

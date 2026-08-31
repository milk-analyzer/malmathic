pub mod arrival;
pub mod candidate;
pub mod enumeration;
pub mod filetime;
pub mod hash;
pub mod lzx;
pub mod mass_encryption;
pub mod observation;
pub mod path;
pub mod volume;
pub mod xpress;

pub use arrival::{Admission, Arrival, ArrivalTimeline, Event, FileLife, Role};
pub use candidate::{Acquisition, Candidate, CandidateId, Evidence, Recovery};
pub use enumeration::{log_odds_of_one_in, Enumeration};
pub use filetime::{from_filetime, Moment};
pub use hash::{FileHash, HashCheck};
pub use mass_encryption::MassEncryption;
pub use observation::{
    ArtifactSource, Observation, ObservationKind, OutOfBandArrival, PersistenceKind,
    SignatureStatus, UrlZone,
};
pub use path::{name_is_executable_extension, NormalizedPath};
pub use volume::{VolumeIdentity, VolumeMatch, VolumeRef};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no Windows installation found on any accessible volume")]
    NoWindowsVolume,

    #[error(
        "volume {0} is BitLocker-encrypted and locked; unlock it with `manage-bde -unlock` first"
    )]
    VolumeLocked(String),

    #[error("access denied opening {0}; malmathic needs to run elevated (or from WinRE)")]
    AccessDenied(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Parse(String),
}

impl Error {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io { context: context.into(), source }
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Error::Parse(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

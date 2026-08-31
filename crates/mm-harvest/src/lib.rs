pub mod amcache;
pub mod arrival;
pub mod defender_log;
pub mod filesystem;
pub mod imphash;
pub mod mass_encryption;
pub mod motw;
pub mod pca;
pub mod pe;
pub mod persistence;
pub mod prefetch;
pub mod quarantine;
pub mod recycle_bin;
pub mod shimcache;
pub mod startup;
pub mod tasks;
#[cfg(any(test, feature = "test-support"))]
pub mod testhive;
pub mod useractivity;
pub mod usn_journal;

use mm_core::Observation;

pub type Harvested = Vec<Observation>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HiveSource {
    Software,
    System,
    NtUser { user: String },
    UsrClass { user: String },
}

impl HiveSource {
    pub fn hive_name(&self) -> String {
        match self {
            HiveSource::Software => "SOFTWARE".into(),
            HiveSource::System => "SYSTEM".into(),
            HiveSource::NtUser { user } => format!("NTUSER.DAT ({user})"),
            HiveSource::UsrClass { user } => format!("UsrClass.dat ({user})"),
        }
    }

    pub fn user(&self) -> Option<&str> {
        match self {
            HiveSource::NtUser { user } | HiveSource::UsrClass { user } => Some(user),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_sources_name_themselves_for_the_report() {
        assert_eq!(HiveSource::Software.hive_name(), "SOFTWARE");
        assert_eq!(HiveSource::System.hive_name(), "SYSTEM");
        assert_eq!(HiveSource::NtUser { user: "bob".into() }.hive_name(), "NTUSER.DAT (bob)");
    }

    #[test]
    fn per_user_hives_carry_their_user() {
        assert_eq!(HiveSource::NtUser { user: "bob".into() }.user(), Some("bob"));
        assert_eq!(HiveSource::UsrClass { user: "bob".into() }.user(), Some("bob"));
        assert_eq!(HiveSource::Software.user(), None);
        assert_eq!(HiveSource::System.user(), None);
    }
}

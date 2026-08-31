use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MassEncryption {
    pub extension: String,
    pub files: u64,
    pub directories: u64,
    pub original_extensions: Vec<(String, u64)>,
    pub roots: Vec<(String, u64)>,
    pub examples: Vec<String>,
    pub note_name: String,
    pub note_size: u64,
    pub note_directories: u64,
    pub note_coverage: f64,
    pub note_example: String,
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
    pub files_scanned: u64,
}

impl MassEncryption {
    #[must_use]
    pub fn window(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        self.earliest.zip(self.latest)
    }
}

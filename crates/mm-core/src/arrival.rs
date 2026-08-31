use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::CandidateId;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArrivalTimeline {
    pub rows_in_journal: usize,
    pub rows_admitted: usize,
    pub files_named: usize,
    pub radius_seconds: i64,
    pub oldest_record: Option<DateTime<Utc>>,
    pub anchors: Vec<Arrival>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Arrival {
    pub candidate: CandidateId,
    pub display_path: String,
    pub probability: f64,
    pub admission: Admission,
    pub directory: Option<String>,
    pub record: u64,
    pub sequence: Option<u16>,
    pub files: Vec<FileLife>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Admission {
    Finding,
    InIncidentWindow,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileLife {
    pub name: String,
    pub display_path: Option<String>,
    pub record: u64,
    pub sequence: u16,
    pub rows: usize,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    pub role: Role,
    pub offset_seconds: f64,
    pub gap_seconds: Option<f64>,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Anchor,
    Candidate { id: CandidateId, probability: f64, below_threshold: bool },
    NotACandidate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Event {
    Appeared { at: DateTime<Utc> },
    Written { at: DateTime<Utc>, extended: bool, overwritten: bool, truncated: bool },
    Closed { at: DateTime<Utc>, after_seconds: f64 },
    Renamed { at: DateTime<Utc>, from: Option<String>, to: Option<String> },
    Deleted { at: DateTime<Utc> },
}

impl Event {
    #[must_use]
    pub fn at(&self) -> DateTime<Utc> {
        match self {
            Event::Appeared { at }
            | Event::Written { at, .. }
            | Event::Closed { at, .. }
            | Event::Renamed { at, .. }
            | Event::Deleted { at } => *at,
        }
    }
}

impl ArrivalTimeline {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

use chrono::{DateTime, Utc};

pub type Moment = DateTime<Utc>;

const EPOCH_DELTA_SECS: i64 = 11_644_473_600;
const TICKS_PER_SEC: i64 = 10_000_000;

const PLAUSIBLE_FROM: i64 = 315_532_800;
const PLAUSIBLE_UNTIL: i64 = 7_258_118_400;

pub fn from_filetime(ticks: u64) -> Option<DateTime<Utc>> {
    if ticks == 0 {
        return None;
    }
    let ticks = i64::try_from(ticks).ok()?;
    let secs = ticks / TICKS_PER_SEC - EPOCH_DELTA_SECS;
    if !(PLAUSIBLE_FROM..PLAUSIBLE_UNTIL).contains(&secs) {
        return None;
    }
    let nanos = (ticks % TICKS_PER_SEC) * 100;

    DateTime::from_timestamp(secs, nanos as u32)
}

pub fn format(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%SZ").to_string()
}

#[must_use]
pub fn format_millis(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn filetime_for(unix_secs: i64) -> u64 {
        ((unix_secs + EPOCH_DELTA_SECS) * TICKS_PER_SEC) as u64
    }

    #[test]
    fn implausibly_old_timestamps_are_rejected() {
        assert!(from_filetime(filetime_for(0)).is_none());
    }

    #[test]
    fn arithmetic_is_exact_at_the_window_edge() {
        let ts = from_filetime(filetime_for(PLAUSIBLE_FROM)).unwrap();
        assert_eq!(format(ts), "1980-01-01 00:00:00Z");
        assert!(from_filetime(filetime_for(PLAUSIBLE_FROM - 1)).is_none());
        assert!(from_filetime(filetime_for(PLAUSIBLE_UNTIL)).is_none());
    }

    #[test]
    fn deliberate_timestomps_are_not_filtered_away() {
        let ts = from_filetime(filetime_for(4_102_444_800)).unwrap();
        assert_eq!(format(ts), "2100-01-01 00:00:00Z");
    }

    #[test]
    fn known_timestamp_converts() {
        let ft = ((1_704_067_200 + EPOCH_DELTA_SECS) * TICKS_PER_SEC) as u64;
        assert_eq!(format(from_filetime(ft).unwrap()), "2024-01-01 00:00:00Z");
    }

    #[test]
    fn sub_second_ticks_survive() {
        let ft = ((1_704_067_200 + EPOCH_DELTA_SECS) * TICKS_PER_SEC + 5_000_000) as u64;
        let ts = from_filetime(ft).unwrap();
        assert_eq!(ts, DateTime::from_timestamp(1_704_067_200, 500_000_000).unwrap());
    }

    #[test]
    fn zero_is_never_a_date() {
        assert!(from_filetime(0).is_none());
    }

    #[test]
    fn out_of_range_values_are_rejected_not_panicked() {
        assert!(from_filetime(u64::MAX).is_none());
        assert!(from_filetime(i64::MAX as u64).is_none());
    }

    #[test]
    fn formatting_is_stable() {
        assert_eq!(format(at(1_704_112_496)), "2024-01-01 12:34:56Z");
    }
}

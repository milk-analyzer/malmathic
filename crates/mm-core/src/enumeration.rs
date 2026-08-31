use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enumeration {
    pub attempted: bool,
    pub files_placed: u64,
    pub files_lost: u64,
}

impl Enumeration {
    pub fn complete(files_placed: u64) -> Self {
        Enumeration { attempted: true, files_placed, files_lost: 0 }
    }

    pub fn partial(files_placed: u64, files_lost: u64) -> Self {
        Enumeration { attempted: true, files_placed, files_lost }
    }

    pub fn not_attempted() -> Self {
        Enumeration { attempted: false, files_placed: 0, files_lost: 0 }
    }

    pub fn fraction(&self) -> Option<f64> {
        if !self.attempted || self.files_placed == 0 {
            return None;
        }
        let known = self.files_placed.saturating_add(self.files_lost) as f64;
        Some((self.files_placed as f64 / known).clamp(f64::MIN_POSITIVE, 1.0))
    }

    pub fn is_complete(&self) -> bool {
        self.attempted && self.files_lost == 0
    }

    pub fn effective_population(&self, admitted: usize) -> Option<f64> {
        self.fraction()?;
        Some(admitted as f64 + self.files_lost as f64)
    }

    pub fn prior_log_odds(&self, admitted: usize) -> Option<f64> {
        let population = self.effective_population(admitted)?;
        Some(log_odds_of_one_in(population))
    }
}

pub fn log_odds_of_one_in(population: f64) -> f64 {
    const EXPECTED_MALICIOUS: f64 = 1.0;
    let n = if population.is_finite() { population.max(2.0) } else { 2.0 };
    (EXPECTED_MALICIOUS / n).ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_walk_leaves_the_population_alone() {
        let e = Enumeration::complete(1_677_974);
        assert_eq!(e.fraction(), Some(1.0));
        assert_eq!(e.effective_population(17_847), Some(17_847.0));
        let prior = e.prior_log_odds(17_847).unwrap();
        assert!((prior - (1.0f64 / 17_847.0).ln()).abs() < 1e-12);
        assert!((prior - -9.7896).abs() < 1e-4, "{prior}");
    }

    #[test]
    fn a_lost_subtree_does_not_raise_the_prior() {
        let complete = Enumeration::complete(1_677_974).prior_log_odds(17_847).unwrap();

        let short = Enumeration::partial(1_674_974, 3_000);
        let degraded = short.prior_log_odds(16_347).unwrap();
        assert!(degraded <= complete, "complete {complete}, degraded {degraded}");

        let old = log_odds_of_one_in(16_347.0);
        assert!(old > complete + 0.08, "the uncorrected prior rose by {}", old - complete);

        let by_density = log_odds_of_one_in(16_347.0 / (1_674_974.0 / 1_677_974.0));
        assert!(
            by_density > complete + 0.08,
            "scaling by completeness left {} of the rise",
            by_density - complete
        );
    }

    #[test]
    fn uniform_loss_does_not_raise_the_prior() {
        let complete = Enumeration::complete(1_500_000).prior_log_odds(15_000).unwrap();
        let degraded = Enumeration::partial(1_000_000, 500_000).prior_log_odds(10_000).unwrap();
        assert!(degraded <= complete, "complete {complete}, degraded {degraded}");

        let old = log_odds_of_one_in(10_000.0);
        assert!(old > complete + 0.4, "the uncorrected prior rose by {}", old - complete);
    }

    #[test]
    fn loss_never_lowers_the_population() {
        let admitted = 5_000;
        let complete = Enumeration::complete(100_000).effective_population(admitted).unwrap();
        for lost in [1u64, 10, 1_000, 50_000, 1_000_000] {
            let partial =
                Enumeration::partial(100_000, lost).effective_population(admitted).unwrap();
            assert!(partial >= complete, "lost {lost} shrank the population");
        }
    }

    #[test]
    fn a_walk_that_did_not_happen_states_no_base_rate() {
        assert_eq!(Enumeration::not_attempted().prior_log_odds(400), None);
        assert_eq!(Enumeration::not_attempted().fraction(), None);
        assert_eq!(Enumeration::partial(0, 12).prior_log_odds(400), None);
    }

    #[test]
    fn the_floor_holds_for_degenerate_populations() {
        assert!(log_odds_of_one_in(0.0).is_finite());
        assert!(log_odds_of_one_in(1.0).is_finite());
        assert!(log_odds_of_one_in(f64::INFINITY).is_finite());
        assert!(log_odds_of_one_in(f64::NAN).is_finite());
        assert!(Enumeration::complete(10).prior_log_odds(0).unwrap().is_finite());
    }
}

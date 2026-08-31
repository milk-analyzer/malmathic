#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Machine {
    pub what: &'static str,
    pub candidates: usize,
    pub effective_population: usize,
    pub rebuilt: usize,
    pub measured: &'static str,
}

impl Machine {
    pub fn ln_population(&self) -> f64 {
        (self.effective_population.min(self.rebuilt).max(2) as f64).ln()
    }

    pub fn prior(&self) -> f64 {
        -self.ln_population()
    }

    pub fn single_feature_ceiling(&self) -> f64 {
        self.ln_population() - CHEAPEST_UBIQUITOUS_ROW
    }
}

pub const SMALLEST_MACHINE: Machine = Machine {
    what: "the smallest machine this tool will report on: a WinRE run whose Amcache \
           and every registry hive failed to parse, rounded down from the 765 measured",
    candidates: 750,
    effective_population: 750,
    rebuilt: 750,
    measured: "2026-08-26, rescore VM_TESTS/test_2/live/report.json --drop-source amcache \
               --drop-source hive gives 765 candidates at a 0.4900 ceiling; the mirror-image \
               degradation of VM_TESTS/test_1, everything dropped BUT the registry, gives 753",
};

pub const CHEAPEST_UBIQUITOUS_ROW: f64 = 1.0;

pub const MEASURED_MACHINES: &[(&str, Machine)] = &[
    (
        "VM_TESTS/test_1/report.json",
        Machine {
            what: "the VM from WinRE, before COM registrations were deferred",
            candidates: 3_744,
            effective_population: 3_744,
            rebuilt: 2_256,
            measured: "2026-08-26, rescore",
        },
    ),
    (
        "VM_TESTS/test_2/live/report.json",
        Machine {
            what: "the VM, healthy, live",
            candidates: 2_256,
            effective_population: 2_256,
            rebuilt: 2_256,
            measured: "2026-08-26, rescore (rebuilds unchanged)",
        },
    ),
    (
        "VM_TESTS/test_2/winre/report.json",
        Machine {
            what: "the VM, healthy, from WinRE",
            candidates: 2_371,
            effective_population: 2_371,
            rebuilt: 2_371,
            measured: "2026-08-26, rescore (rebuilds unchanged)",
        },
    ),
    (
        "VM_TESTS/test_3/report.json",
        Machine {
            what: "the VM, clean, after the wreckage/lost-files split",
            candidates: 2_448,
            effective_population: 2_452,
            rebuilt: 2_448,
            measured: "2026-08-26, rescore (rebuilt prior -7.8030)",
        },
    ),
    (
        "VM_TESTS/test_4/report.json",
        Machine {
            what: "the VM with njRAT planted — the detection end of the constraint",
            candidates: 2_412,
            effective_population: 2_416,
            rebuilt: 2_412,
            measured: "2026-08-26, rescore (rebuilt prior -7.7882; findings 0.9990 and 0.9973)",
        },
    ),
    (
        "VM_TESTS/test_5/report.json",
        Machine {
            what: "the njRAT VM from WinRE, after Defender had cleaned up",
            candidates: 2_415,
            effective_population: 2_419,
            rebuilt: 2_415,
            measured: "2026-08-28, rescore (rebuilt prior -7.7895; one finding, 0.9804)",
        },
    ),
    (
        "VM_TESTS/test_6_image_snapshot4/report.json",
        Machine {
            what: "the njRAT VM read from a VMDK image rather than an attached disk",
            candidates: 2_847,
            effective_population: 2_851,
            rebuilt: 2_847,
            measured: "2026-08-28, rescore (rebuilt prior -7.9540; 2 as-written \
                       findings, 0 after the COM replay)",
        },
    ),
    (
        "VM_TESTS/test_7_ransomware/report.json",
        Machine {
            what: "the same machine after ransomware ran: the tool's best result, and \
                   the one that was pinned by nothing",
            candidates: 2_868,
            effective_population: 2_872,
            rebuilt: 2_868,
            measured: "2026-08-28, rescore (rebuilt prior -7.9614; 3 findings as \
                       written, 0.7572 / 0.6541 / 0.5343)",
        },
    ),
    (
        "malmathic-case/report.self-excluded.json",
        Machine {
            what: "the reference laptop, live, with this project's own build tree excluded \
                   (not published; see the note above the row)",
            candidates: 19_270,
            effective_population: 20_263,
            rebuilt: 17_847,
            measured: "2026-08-26, rescore (rebuilt prior -9.7896, ceiling 0.2333)",
        },
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_computes_its_prior_from_its_population() {
        let vm = Machine {
            what: "the VM, healthy, live",
            candidates: 2_256,
            effective_population: 2_256,
            rebuilt: 2_256,
            measured: "2026-08-26, rescore VM_TESTS/test_2/live/report.json",
        };
        assert!((vm.ln_population() - 7.7213).abs() < 0.0001, "{}", vm.ln_population());
        assert!((vm.prior() - -7.7213).abs() < 0.0001, "{}", vm.prior());
    }

    #[test]
    fn the_floor_is_below_every_dataset_in_the_tree() {
        for (path, machine) in MEASURED_MACHINES {
            assert!(
                SMALLEST_MACHINE.ln_population() < machine.ln_population(),
                "{path} ({}) prices against {:.0} candidates, at or below the {} the guards \
                 assume as their floor — the floor is no longer a floor and must be re-derived \
                 from that run",
                machine.what,
                machine.ln_population().exp(),
                SMALLEST_MACHINE.candidates
            );
        }
    }

    #[test]
    fn the_floor_is_above_the_population_where_a_clean_machine_accuses_itself() {
        const STRONGEST_INNOCENT_STACK: f64 = 6.6;
        let crossover = STRONGEST_INNOCENT_STACK.exp();
        assert!((crossover - 735.1).abs() < 0.5, "the crossover moved: {crossover}");
        assert!(
            SMALLEST_MACHINE.candidates as f64 > crossover,
            "the floor ({}) is at or below the population where the clean VM's own \
             +{STRONGEST_INNOCENT_STACK} installer stack reaches even odds ({crossover:.0}); \
             below that no per-feature bound can keep a clean machine quiet",
            SMALLEST_MACHINE.candidates
        );
    }

    #[test]
    fn the_single_feature_ceiling_is_the_floor_less_a_free_companion_row() {
        let ceiling = SMALLEST_MACHINE.single_feature_ceiling();
        assert!((ceiling - (6.6201 - 1.0)).abs() < 0.001, "{ceiling}");
    }
}

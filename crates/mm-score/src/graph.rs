use std::collections::{HashMap, HashSet};

use mm_core::{Candidate, CandidateId, Observation};

struct DisjointSet {
    parent: Vec<usize>,
    path: Vec<Option<String>>,
}

impl DisjointSet {
    fn new() -> Self {
        DisjointSet { parent: Vec::new(), path: Vec::new() }
    }

    fn make(&mut self) -> usize {
        let id = self.parent.len();
        self.parent.push(id);
        self.path.push(None);
        id
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn path_of(&mut self, x: usize) -> Option<&str> {
        let root = self.find(x);
        self.path[root].as_deref()
    }

    fn commit_path(&mut self, x: usize, key: &str) {
        let root = self.find(x);
        if self.path[root].is_none() {
            self.path[root] = Some(key.to_string());
        }
    }

    fn union(&mut self, a: usize, b: usize) -> usize {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[rb] = ra;
            if self.path[ra].is_none() {
                self.path[ra] = self.path[rb].take();
            }
        }
        ra
    }
}

pub fn build(observations: Vec<Observation>, prior_log_odds: f64) -> Vec<Candidate> {
    let mut sets = DisjointSet::new();
    let mut by_path: HashMap<String, usize> = HashMap::new();
    let mut by_hash: HashMap<String, usize> = HashMap::new();
    let mut fragments: Vec<Vec<Observation>> = Vec::new();

    for observation in observations {
        if !observation.identifies_something() {
            continue;
        }

        let path_key = observation.path.as_ref().map(|p| p.key().to_string());
        let hash_keys = hash_keys(&observation);

        let mut joined: Option<usize> = None;
        if let Some(key) = &path_key {
            if let Some(&idx) = by_path.get(key) {
                joined = Some(sets.find(idx));
            }
        }
        for key in &hash_keys {
            let Some(&idx) = by_hash.get(key) else { continue };
            let root = sets.find(idx);
            let mine = match joined {
                Some(existing) => sets.path_of(existing).map(str::to_string),
                None => path_key.clone(),
            };
            if let (Some(mine), Some(theirs)) = (&mine, sets.path_of(root)) {
                if mine != theirs {
                    continue;
                }
            }
            joined = Some(match joined {
                Some(existing) => sets.union(existing, root),
                None => root,
            });
        }

        let root = match joined {
            Some(root) => root,
            None => {
                let id = sets.make();
                fragments.push(Vec::new());
                id
            }
        };

        if let Some(key) = path_key {
            sets.commit_path(root, &key);
            by_path.entry(key).or_insert(root);
        }
        for key in hash_keys {
            by_hash.entry(key).or_insert(root);
        }

        fragments[root].push(observation);
    }

    let mut merged: HashMap<usize, Vec<Observation>> = HashMap::new();
    for (idx, observations) in fragments.into_iter().enumerate() {
        if observations.is_empty() {
            continue;
        }
        let root = sets.find(idx);
        merged.entry(root).or_default().extend(observations);
    }

    let mut roots: Vec<usize> = merged.keys().copied().collect();
    roots.sort_unstable();

    roots
        .into_iter()
        .enumerate()
        .map(|(n, root)| {
            let mut candidate = Candidate::new(CandidateId(n as u32), prior_log_odds);
            for observation in merged.remove(&root).unwrap_or_default() {
                candidate.observe(observation);
            }
            candidate
        })
        .collect()
}

pub fn link_shared_digests(candidates: &mut [Candidate]) -> usize {
    for candidate in candidates.iter_mut() {
        candidate
            .observations
            .retain(|o| !matches!(o.kind, mm_core::ObservationKind::SharedDigestElsewhere { .. }));
    }

    let mut by_digest: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if candidate.hash_checks.iter().any(|check| !check.agrees) {
            continue;
        }
        if candidate.path.as_ref().is_none_or(|p| !p.is_located()) {
            continue;
        }
        for key in digest_keys(&candidate.hash) {
            by_digest.entry(key).or_default().push(i);
        }
    }

    let mut parent: Vec<usize> = (0..candidates.len()).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut keys: Vec<&String> = by_digest.keys().collect();
    keys.sort_unstable();
    for key in keys {
        let members = &by_digest[key];
        for window in members.windows(2) {
            let (a, b) = (root(&mut parent, window[0]), root(&mut parent, window[1]));
            if a != b {
                parent[a] = b;
            }
        }
    }
    let mut by_root: HashMap<usize, Vec<usize>> = HashMap::new();
    let indexed: Vec<usize> = {
        let mut v: Vec<usize> = by_digest
            .values()
            .flat_map(|m| m.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        v.sort_unstable();
        v
    };
    for i in indexed {
        let r = root(&mut parent, i);
        by_root.entry(r).or_default().push(i);
    }
    let mut groups: Vec<Vec<usize>> = by_root.into_values().collect();
    groups.sort_unstable_by_key(|g| g[0]);

    let mut linked = 0usize;
    for members in &groups {
        if members.len() < 2 {
            continue;
        }
        for &i in members {
            let Some(mine) = candidates[i].path.clone() else { continue };
            let my_name = mine.file_name().unwrap_or_default().to_string();
            let my_zone = crate::zone::classify(&mine);
            let others: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&j| j != i)
                .filter(|&j| candidates[j].path.as_ref().is_some_and(|p| p.key() != mine.key()))
                .collect();
            if others.is_empty() {
                continue;
            }
            let best = others
                .iter()
                .copied()
                .max_by_key(|&j| {
                    let theirs = candidates[j].path.as_ref().expect("filtered above");
                    let renamed =
                        !theirs.file_name().unwrap_or_default().eq_ignore_ascii_case(&my_name);
                    let elsewhere = crate::zone::classify(theirs) != my_zone;
                    (u8::from(renamed), u8::from(elsewhere))
                })
                .expect("others is non-empty");
            let theirs = candidates[best].path.clone().expect("filtered above");
            let algorithm = candidates[i]
                .hash
                .agreeing_algorithm(&candidates[best].hash)
                .unwrap_or("digest")
                .to_string();
            let source = candidates[i]
                .observations
                .iter()
                .find(|o| o.hash.agrees_with(&candidates[best].hash))
                .map(|o| o.source.clone())
                .unwrap_or(mm_core::ArtifactSource::FileContent);
            candidates[i].observe(mm_core::Observation::about_path(
                source,
                mine,
                mm_core::ObservationKind::SharedDigestElsewhere {
                    path: theirs,
                    algorithm,
                    copies: others.len() as u32,
                },
            ));
            linked += 1;
        }
    }
    linked
}

fn digest_keys(h: &mm_core::FileHash) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(v) = h.sha256_hex() {
        keys.push(format!("sha256:{v}"));
    }
    if let Some(v) = h.sha1_hex() {
        keys.push(format!("sha1:{v}"));
    }
    if let Some(v) = h.md5_hex() {
        keys.push(format!("md5:{v}"));
    }
    keys
}

fn hash_keys(observation: &Observation) -> Vec<String> {
    let h = &observation.hash;
    let mut keys = Vec::new();
    if let Some(v) = h.sha256_hex() {
        keys.push(format!("sha256:{v}"));
    }
    if let Some(v) = h.sha1_hex() {
        keys.push(format!("sha1:{v}"));
    }
    if let Some(v) = h.md5_hex() {
        keys.push(format!("md5:{v}"));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{ArtifactSource, FileHash, NormalizedPath, ObservationKind, PersistenceKind};

    const PRIOR: f64 = -9.2;

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn at_path(source: ArtifactSource, p: &str) -> Observation {
        Observation::about_path(
            source,
            path(p),
            ObservationKind::Executed { when: None, run_count: None },
        )
    }

    fn at_hash(source: ArtifactSource, bytes: &[u8]) -> Observation {
        Observation::about_hash(source, FileHash::compute(bytes), ObservationKind::HashRecovered)
    }

    #[test]
    fn different_spellings_of_one_path_collapse() {
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\Users\\bob\\x.exe"),
            at_path(ArtifactSource::ShimCache, "\\??\\C:\\Users\\bob\\x.exe"),
            at_path(ArtifactSource::Prefetch, "\\VOLUME{01d7}\\USERS\\BOB\\X.EXE"),
            at_path(ArtifactSource::Amcache, "c:\\users\\bob\\x.exe"),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].observations.len(), 4);
    }

    #[test]
    fn distinct_files_stay_distinct() {
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\Users\\bob\\x.exe"),
            at_path(ArtifactSource::Mft, "C:\\Users\\bob\\y.exe"),
        ];
        assert_eq!(build(observations, PRIOR).len(), 2);
    }

    #[test]
    fn an_observation_carrying_both_identities_bridges_two_fragments() {
        let hash = FileHash::compute(b"payload");
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\Users\\bob\\x.exe"),
            at_hash(ArtifactSource::DefenderLog { event_id: 1116 }, b"payload"),
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(hash),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1, "the bridging observation should have merged them");
        assert_eq!(candidates[0].observations.len(), 3);
        assert!(candidates[0].hash.sha256.is_some());
        assert!(candidates[0].path.is_some());
    }

    #[test]
    fn unrelated_identities_are_not_merged_on_resemblance() {
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\Users\\bob\\x.exe"),
            at_hash(ArtifactSource::DefenderLog { event_id: 1116 }, b"payload"),
        ];
        assert_eq!(build(observations, PRIOR).len(), 2);
    }

    #[test]
    fn merging_works_when_the_bridge_arrives_last() {
        let mut observations = vec![
            at_path(ArtifactSource::Mft, "C:\\x.exe"),
            at_path(ArtifactSource::ShimCache, "C:\\x.exe"),
            at_hash(ArtifactSource::DefenderLog { event_id: 1116 }, b"payload"),
            at_hash(ArtifactSource::DefenderQuarantine, b"payload"),
        ];
        observations.push(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"payload")),
        );

        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].observations.len(), 5, "no observation may be lost in a merge");
    }

    #[test]
    fn merges_are_transitive() {
        let observations = vec![
            at_path(ArtifactSource::Mft, r"C:\a.exe"),
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\a.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"one")),
            at_hash(ArtifactSource::DefenderQuarantine, b"one"),
            at_hash(ArtifactSource::DefenderLog { event_id: 1117 }, b"one"),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1, "a shared hash joins a path fragment to hash-only ones");
        assert_eq!(candidates[0].observations.len(), 4);
    }

    #[test]
    fn a_shared_digest_does_not_merge_two_different_paths() {
        let observations = vec![
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\Program Files\App\svc.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"one")),
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\Users\bob\Documents\svc.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"one")),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 2, "content equality is not file identity");
        let mut labels: Vec<String> = candidates.iter().map(|c| c.label()).collect();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                r"C:\Program Files\App\svc.exe".to_string(),
                r"C:\Users\bob\Documents\svc.exe".to_string()
            ]
        );
    }

    #[test]
    fn the_split_is_the_same_whichever_path_is_read_first() {
        let a = Observation::about_path(
            ArtifactSource::Amcache,
            path(r"C:\Program Files\App\svc.exe"),
            ObservationKind::HashRecovered,
        )
        .with_hash(FileHash::compute(b"one"));
        let b = Observation::about_path(
            ArtifactSource::Mft,
            path(r"C:\Users\bob\Documents\svc.exe"),
            ObservationKind::HashRecovered,
        )
        .with_hash(FileHash::compute(b"one"));
        assert_eq!(build(vec![a.clone(), b.clone()], PRIOR).len(), 2);
        assert_eq!(build(vec![b, a], PRIOR).len(), 2);
    }

    #[test]
    fn a_hash_only_fragment_still_joins_the_path_that_carries_that_hash() {
        let observations = vec![
            at_hash(ArtifactSource::DefenderQuarantine, b"payload"),
            Observation::about_path(
                ArtifactSource::Amcache,
                path(r"C:\Users\bob\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::compute(b"payload")),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].observations.len(), 2);
    }

    #[test]
    fn hash_only_candidates_survive() {
        let candidates = build(vec![at_hash(ArtifactSource::Amcache, b"gone")], PRIOR);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].path.is_none());
        assert!(candidates[0].hash.sha256.is_some());
        assert!(candidates[0].label().starts_with("<no path known>"));
    }

    #[test]
    fn observations_identifying_nothing_are_dropped() {
        let empty = Observation {
            source: ArtifactSource::Mft,
            kind: ObservationKind::HashRecovered,
            path: None,
            hash: FileHash::default(),
        };
        assert!(build(vec![empty], PRIOR).is_empty());
        assert!(build(vec![], PRIOR).is_empty());
    }

    #[test]
    fn candidate_ids_are_assigned_densely_and_in_order() {
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\a.exe"),
            at_path(ArtifactSource::Mft, "C:\\b.exe"),
            at_path(ArtifactSource::Mft, "C:\\c.exe"),
        ];
        let candidates = build(observations, PRIOR);
        let ids: Vec<u32> = candidates.iter().map(|c| c.id.0).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn merged_candidates_accumulate_corroboration() {
        let observations = vec![
            at_path(ArtifactSource::Mft, "C:\\x.exe"),
            at_path(ArtifactSource::Amcache, "C:\\x.exe"),
            Observation::about_path(
                ArtifactSource::Registry { hive: "SOFTWARE".into(), key: "Run".into() },
                path("C:\\x.exe"),
                ObservationKind::Persistence {
                    kind: PersistenceKind::RunKey,
                    raw_value: "C:\\x.exe".into(),
                },
            ),
        ];
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].corroboration(), 3, "filesystem + execution + persistence");
    }

    #[test]
    fn grouping_scales_to_a_realistic_artifact_count() {
        let mut observations = Vec::new();
        for i in 0..20_000 {
            observations
                .push(at_path(ArtifactSource::Mft, &format!("C:\\dir{}\\f{i}.exe", i % 100)));
        }
        let candidates = build(observations, PRIOR);
        assert_eq!(candidates.len(), 20_000);
    }
}

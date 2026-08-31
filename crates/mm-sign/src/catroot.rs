use chrono::{DateTime, Utc};
use mm_raw::Volume;
use std::io::{Read, Seek};

use crate::catalog::{CatalogIndex, CATROOT_DIRECTORIES, MAX_CATALOG_BYTES};
use crate::trust::TrustStore;

pub fn index_volume<R: Read + Seek>(volume: &Volume<R>, trust: &TrustStore) -> CatalogIndex {
    index_volume_at(volume, trust, crate::now())
}

pub fn index_volume_with_progress<R: Read + Seek>(
    volume: &Volume<R>,
    trust: &TrustStore,
    progress: &mut dyn FnMut(u64, u64),
) -> CatalogIndex {
    let now = crate::now();
    let mut index = CatalogIndex::new();
    let work: Vec<Vec<DirectoryCatalog>> =
        CATROOT_DIRECTORIES.iter().map(|d| catalog_entries(volume, d)).collect();
    let total: u64 = work.iter().map(|entries| entries.len() as u64).sum();

    let mut done = 0u64;
    for entries in work {
        let count = entries.len() as u64;
        index_entries(volume, entries, trust, now, &mut index, &mut |in_directory| {
            progress(done + in_directory, total)
        });
        done += count;
    }
    progress(total, total);
    index
}

pub fn index_volume_at<R: Read + Seek>(
    volume: &Volume<R>,
    trust: &TrustStore,
    now: DateTime<Utc>,
) -> CatalogIndex {
    let mut index = CatalogIndex::new();
    for directory in CATROOT_DIRECTORIES {
        index_directory_at(volume, directory, trust, now, &mut index);
    }
    index
}

pub fn index_directory_at<R: Read + Seek>(
    volume: &Volume<R>,
    directory: &str,
    trust: &TrustStore,
    now: DateTime<Utc>,
    index: &mut CatalogIndex,
) {
    let entries = catalog_entries(volume, directory);
    index_entries(volume, entries, trust, now, index, &mut |_| {});
}

struct DirectoryCatalog {
    name: String,
    record: u64,
}

fn catalog_entries<R: Read + Seek>(volume: &Volume<R>, directory: &str) -> Vec<DirectoryCatalog> {
    let mut entries: Vec<DirectoryCatalog> = volume
        .list_directory_entries(directory)
        .into_iter()
        .filter(|entry| is_catalog_name(&entry.name))
        .map(|entry| DirectoryCatalog { name: entry.name, record: entry.record })
        .collect();
    entries.sort_by_key(|entry| entry.record);
    entries
}

fn index_entries<R: Read + Seek>(
    volume: &Volume<R>,
    entries: Vec<DirectoryCatalog>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    index: &mut CatalogIndex,
    progress: &mut dyn FnMut(u64),
) {
    for (done, entry) in entries.into_iter().enumerate() {
        progress(done as u64);
        let Ok(bytes) = volume.read_record_capped(entry.record, MAX_CATALOG_BYTES) else {
            index.note_unreadable();
            continue;
        };
        let _ = index.add(&entry.name, &bytes, trust, now);
    }
}

fn is_catalog_name(name: &str) -> bool {
    name.len() > 4
        && name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(".cat"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_cat_files_are_offered_to_the_parser() {
        assert!(is_catalog_name("Package_1.cat"));
        assert!(is_catalog_name("OEM36.CAT"));
        assert!(!is_catalog_name(".cat"));
        assert!(!is_catalog_name("catdb"));
        assert!(!is_catalog_name("Package_1.cat.new"));
        assert!(!is_catalog_name(""));
    }
}

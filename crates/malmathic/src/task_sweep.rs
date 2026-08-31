#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use mm_core::Observation;
use mm_raw::{DirectoryEntry, Volume};

use crate::hostile_index::{metered, Counted, Meter};
use crate::testimage::{Builder, IndexLayout, Presence, ROOT_RECORD};

const STORE: &str = r"\Windows\System32\Tasks";

const TASKS: usize = 209;

const COMPONENTS: usize = 24;
const TASKS_PER_COMPONENT: usize = 8;
const TOP_LEVEL_TASKS: usize = 17;

const PREFIX_CHILDREN: usize = 70;

fn task_store() -> Builder {
    task_store_parts().0
}

fn task_store_parts() -> (Builder, Vec<u64>) {
    let mut image = Builder::with_records(1_200);

    let windows = image.directory(ROOT_RECORD, "Windows");
    let system32 = image.directory(windows, "System32");
    populate(&mut image, system32, "sys");

    let tasks = image.directory(system32, "Tasks");
    image.spill_index(tasks, IndexLayout::LargeInBase);
    for i in 0..TOP_LEVEL_TASKS {
        let name = format!("Top{i:03}");
        image.resident_file(tasks, &name, &task_xml(&name), Presence::Live);
    }

    let microsoft = image.directory(tasks, "Microsoft");
    let windows_tasks = image.directory(microsoft, "Windows");
    image.spill_index(windows_tasks, IndexLayout::LargeInBase);
    let mut components = Vec::new();
    for c in 0..COMPONENTS {
        let component = image.directory(windows_tasks, &format!("Cmp{c:03}"));
        image.spill_index(component, IndexLayout::LargeInBase);
        for t in 0..TASKS_PER_COMPONENT {
            let name = format!("T{c:03}{t:02}");
            image.resident_file(component, &name, &task_xml(&name), Presence::Live);
        }
        components.push(component);
    }
    (image, components)
}

fn populate(image: &mut Builder, directory: u64, tag: &str) {
    image.spill_index(directory, IndexLayout::LargeInBase);
    for i in 0..PREFIX_CHILDREN {
        image.resident_file(directory, &format!("{tag}{i:04}.dll"), b"MZ", Presence::Live);
    }
}

fn task_xml(name: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <Task version=\"1.2\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         <RegistrationInfo><URI>\\{name}</URI></RegistrationInfo>\n\
         <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\n\
         <Actions Context=\"Author\"><Exec>\n\
         <Command>C:\\Program Files\\Vendor\\{name}.exe</Command>\n\
         </Exec></Actions>\n\
         </Task>\n"
    )
    .into_bytes()
}

fn old_walk_tasks<R: std::io::Read + std::io::Seek>(
    volume: &Volume<R>,
    directory: &str,
    depth: usize,
    visit: &mut dyn FnMut(&str, &[u8]),
) {
    const TASK_DEPTH: usize = 8;
    const TASK: usize = 2 * 1024 * 1024;

    if depth > TASK_DEPTH {
        return;
    }
    for name in volume.list_directory(directory) {
        let child = format!("{}\\{name}", directory.trim_end_matches('\\'));
        match volume.read_capped(&child, TASK) {
            Ok(bytes) if !bytes.is_empty() => visit(&child, &bytes),
            _ => old_walk_tasks(volume, &child, depth + 1, visit),
        }
    }
}

fn observations_of_the_old_sweep(volume: &Volume<Counted>) -> Vec<Observation> {
    let mut out = Vec::new();
    old_walk_tasks(volume, STORE, 0, &mut |path, bytes| {
        out.extend(mm_harvest::tasks::harvest(bytes, path));
    });
    out
}

fn observations_of_the_stage(volume: &Volume<Counted>) -> Vec<Observation> {
    let mut out = Vec::new();
    let mut coverage = mm_report::Coverage::default();
    crate::pipeline::harvest_tasks(volume, &mut out, &mut coverage, crate::progress::Style::Silent);
    out
}

fn as_text(observations: &[Observation]) -> Vec<String> {
    let mut text: Vec<String> = observations
        .iter()
        .map(|o| serde_json::to_string(o).expect("an observation serializes"))
        .collect();
    text.sort();
    text
}

struct Cost {
    reads: usize,
    bytes: u64,
}

fn cost_of(meter: &Meter, run: impl FnOnce()) -> Cost {
    let before = meter.snapshot();
    run();
    let after = meter.snapshot().since(&before);
    Cost { reads: after.reads, bytes: after.bytes }
}

#[test]
fn the_fixture_holds_the_number_of_tasks_the_vm_did() {
    let (volume, _) = metered(task_store());
    let mut paths = BTreeSet::new();
    old_walk_tasks(&volume, STORE, 0, &mut |path, _| {
        paths.insert(path.to_string());
    });
    assert_eq!(paths.len(), TASKS, "the fixture is meant to hold {TASKS} task definitions");
}

#[test]
fn the_stage_reports_exactly_what_the_old_sweep_reported() {
    let (volume, _) = metered(task_store());
    let before = as_text(&observations_of_the_old_sweep(&volume));
    let after = as_text(&observations_of_the_stage(&volume));

    assert!(!before.is_empty(), "the old sweep found nothing, so this proves nothing");
    assert_eq!(before.len(), after.len(), "the stage reports a different number of observations");
    assert_eq!(before, after, "the stage reports different observations");
}

#[test]
fn every_definition_still_contributes_an_observation() {
    let (volume, _) = metered(task_store());
    let observations = observations_of_the_stage(&volume);
    let paths: BTreeSet<String> =
        observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect();
    assert!(!paths.is_empty(), "a task harvest with no paths in it is not a harvest");
    assert_eq!(observations.len(), TASKS, "one observation per task definition");
}

#[test]
fn an_unreadable_component_costs_its_branch_and_not_the_run() {
    const DOOMED: usize = 3;

    let damaged = |image: &mut Builder, component: u64| {
        image.sparse_index_buffer(component, 0);
    };

    let (mut image, components) = task_store_parts();
    damaged(&mut image, components[DOOMED]);
    let (volume, _) = metered(image);

    let before = as_text(&observations_of_the_old_sweep(&volume));
    let after = as_text(&observations_of_the_stage(&volume));

    assert_eq!(before, after, "the two sweeps disagree about a refused directory");
    assert!(after.len() < TASKS, "the damaged component was supposed to cost its definitions");
    assert!(
        after.len() >= TASKS - TASKS_PER_COMPONENT,
        "a refused component cost {} definitions, not the {TASKS_PER_COMPONENT} in it",
        TASKS - after.len()
    );
}

#[test]
fn the_sweep_no_longer_pays_for_the_path_above_it() {
    let (volume, meter) = metered(task_store());

    let mut sink = Vec::new();
    let old = cost_of(&meter, || sink = observations_of_the_old_sweep(&volume));
    let old_count = sink.len();

    let new = cost_of(&meter, || sink = observations_of_the_stage(&volume));
    assert_eq!(sink.len(), old_count, "the two sweeps must harvest the same thing");

    println!("  scheduled tasks over {TASKS} definitions");
    println!("    before   {:>8} reads   {:>10} bytes", old.reads, old.bytes);
    println!("    after    {:>8} reads   {:>10} bytes", new.reads, new.bytes);
    println!(
        "    ratio    {:>7.1}x         {:>9.1}x",
        old.reads as f64 / new.reads.max(1) as f64,
        old.bytes as f64 / new.bytes.max(1) as f64
    );

    assert!(
        new.reads * 3 < old.reads,
        "the sweep took {} reads where the old one took {}",
        new.reads,
        old.reads
    );
    assert!(
        new.bytes * 5 < old.bytes,
        "the sweep read {} bytes where the old one read {}",
        new.bytes,
        old.bytes
    );
}

#[test]
fn the_cost_no_longer_grows_with_the_depth_of_the_store() {
    const SMALL: usize = 20;

    fn cost_at_depth(extra: usize) -> (usize, usize) {
        let mut image = Builder::with_records(1_200);
        let mut here = ROOT_RECORD;
        for level in 0..extra {
            here = image.directory(here, &format!("level{level}"));
            populate(&mut image, here, &format!("l{level}"));
        }
        let windows = image.directory(here, "Windows");
        let system32 = image.directory(windows, "System32");
        let tasks = image.directory(system32, "Tasks");
        image.spill_index(tasks, IndexLayout::LargeInBase);
        for i in 0..SMALL {
            let name = format!("Task{i:03}");
            image.resident_file(tasks, &name, &task_xml(&name), Presence::Live);
        }

        let prefix: String = (0..extra).map(|l| format!("\\level{l}")).collect();
        let path = format!("{prefix}{STORE}");

        let (volume, meter) = metered(image);
        let mut seen = 0usize;

        let old = cost_of(&meter, || {
            old_walk_tasks(&volume, &path, 0, &mut |_, _| seen += 1);
        })
        .reads;
        assert_eq!(seen, SMALL, "the old sweep must find every task at depth {extra}");

        seen = 0;
        let new = cost_of(&meter, || {
            let root = volume.resolve(&path).expect("the store resolves");
            let entries = volume.list_directory_entries_of_record(root).expect("the store lists");
            walk_by_record(&volume, &path, entries, &mut |_, _| seen += 1);
        })
        .reads;
        assert_eq!(seen, SMALL, "the new sweep must find every task at depth {extra}");

        (old, new)
    }

    const LEVELS: usize = 4;
    const PER_LEVEL_BUDGET: usize = 8;

    let (old_shallow, new_shallow) = cost_at_depth(0);
    let (old_deep, new_deep) = cost_at_depth(LEVELS);

    println!("  {LEVELS} extra levels above the store, {SMALL} definitions:");
    println!(
        "    old   {old_shallow} -> {old_deep} reads   ({} per added level)",
        (old_deep - old_shallow) / LEVELS
    );
    println!(
        "    new   {new_shallow} -> {new_deep} reads   ({} per added level)",
        (new_deep - new_shallow) / LEVELS
    );

    assert!(
        old_deep - old_shallow >= LEVELS * SMALL,
        "the old sweep was supposed to cost one enumeration per task per level: \
         {old_shallow} -> {old_deep}"
    );
    assert!(
        new_deep - new_shallow <= LEVELS * PER_LEVEL_BUDGET,
        "the new sweep grew by {} reads over {LEVELS} levels, more than the {PER_LEVEL_BUDGET} \
         per level one path resolution can account for: {new_shallow} -> {new_deep}",
        new_deep - new_shallow
    );
    assert!(
        new_deep - new_shallow < SMALL,
        "the new sweep's growth with depth must not scale with the {SMALL} tasks in the store: \
         {new_shallow} -> {new_deep}"
    );
}

fn walk_by_record(
    volume: &Volume<Counted>,
    directory: &str,
    entries: Vec<DirectoryEntry>,
    visit: &mut dyn FnMut(&str, &[u8]),
) {
    for entry in entries {
        let child = format!("{}\\{}", directory.trim_end_matches('\\'), entry.name);
        match volume.read_record_capped(entry.record, 2 * 1024 * 1024) {
            Ok(bytes) if !bytes.is_empty() => visit(&child, &bytes),
            _ => {
                if let Ok(children) = volume.list_directory_entries_of_record(entry.record) {
                    walk_by_record(volume, &child, children, visit);
                }
            }
        }
    }
}

fn walk_by_record_asking_first(
    volume: &Volume<Counted>,
    directory: &str,
    entries: Vec<DirectoryEntry>,
    visit: &mut dyn FnMut(&str, &[u8]),
) {
    for entry in entries {
        let child = format!("{}\\{}", directory.trim_end_matches('\\'), entry.name);
        if let Ok(children) = volume.list_directory_entries_of_record(entry.record) {
            if !children.is_empty() {
                walk_by_record_asking_first(volume, &child, children, visit);
                continue;
            }
        }
        if let Ok(bytes) = volume.read_record_capped(entry.record, 2 * 1024 * 1024) {
            if !bytes.is_empty() {
                visit(&child, &bytes);
            }
        }
    }
}

#[test]
fn asking_the_record_is_measured_against_waiting_for_a_failed_read() {
    let (volume, meter) = metered(task_store());
    let root = volume.resolve(STORE).expect("the store resolves");

    let mut read = 0usize;
    let shipped = cost_of(&meter, || {
        let entries = volume.list_directory_entries_of_record(root).expect("the store lists");
        walk_by_record(&volume, STORE, entries, &mut |_, _| read += 1);
    });

    let mut asked = 0usize;
    let alternative = cost_of(&meter, || {
        let entries = volume.list_directory_entries_of_record(root).expect("the store lists");
        walk_by_record_asking_first(&volume, STORE, entries, &mut |_, _| asked += 1);
    });

    println!("  {TASKS} definitions in 27 directories, records carried either way:");
    println!(
        "    wait for a failed read {:>6} reads   {:>9} bytes   <- shipped",
        shipped.reads, shipped.bytes
    );
    println!(
        "    ask the record first   {:>6} reads   {:>9} bytes",
        alternative.reads, alternative.bytes
    );

    assert_eq!(read, TASKS, "the shipped order lost definitions");
    assert_eq!(asked, TASKS, "the alternative lost definitions");

    assert!(
        shipped.reads <= alternative.reads,
        "waiting for a failed read is no longer the cheaper order: {} reads against {}",
        shipped.reads,
        alternative.reads
    );

    assert!(
        alternative.reads * 2 < shipped.reads * 3,
        "the two orders have diverged far enough to be worth re-arguing: {} against {}",
        shipped.reads,
        alternative.reads
    );
}

#[test]
fn no_definition_is_visited_twice() {
    let (volume, _) = metered(task_store());
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let root = volume.resolve(STORE).expect("the store resolves");
    let entries = volume.list_directory_entries_of_record(root).expect("the store lists");
    walk_by_record(&volume, STORE, entries, &mut |path, _| {
        *seen.entry(path.to_string()).or_default() += 1;
    });
    assert_eq!(seen.len(), TASKS);
    assert!(seen.values().all(|n| *n == 1), "a definition was visited more than once");
}

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mm_harvest::pca;

const HOT: [&str; 3] = ["\\temp\\", "\\downloads\\", "\\appdata\\"];

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: pcastudy <pca directory> [sole user profile]");
        std::process::exit(2);
    };
    let dir = PathBuf::from(dir);
    let profile = args.next();

    for name in ["PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt"] {
        let launch_dic = name.contains("AppLaunch");
        let path = dir.join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            println!("\n=== {name} — not present ===");
            continue;
        };

        let rows =
            if launch_dic { pca::parse_app_launch(&bytes) } else { pca::parse_general_db(&bytes) };
        let out = if launch_dic {
            pca::harvest_app_launch(&bytes)
        } else {
            pca::harvest_general_db(&bytes, profile.as_deref())
        };

        println!("\n=== {name} — {} bytes ===", bytes.len());
        println!(
            "rows {}   observations {}   unattributed {}   malformed {}",
            out.rows,
            out.observations.len(),
            out.unattributed,
            out.malformed
        );

        let keys: BTreeSet<&str> =
            out.observations.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key()).collect();
        println!("unique paths {}", keys.len());

        let timed = rows.iter().filter(|r| r.when.is_some()).count();
        println!("rows with a parsed timestamp {timed} of {}", rows.len());
        if let (Some(lo), Some(hi)) =
            (rows.iter().filter_map(|r| r.when).min(), rows.iter().filter_map(|r| r.when).max())
        {
            println!("time span {lo}  ..  {hi}");
        }

        let (mut gone, mut hot) = (0usize, 0usize);
        for key in &keys {
            if Path::new(&format!("C:{key}")).exists() {
                continue;
            }
            gone += 1;
            let lowered = key.to_ascii_lowercase();
            if HOT.iter().any(|z| lowered.contains(z)) {
                hot += 1;
            }
        }
        if !keys.is_empty() {
            println!(
                "no longer on this disk: {gone} of {} ({:.1}%), of which {hot} under Temp/Downloads/AppData",
                keys.len(),
                100.0 * gone as f64 / keys.len() as f64
            );
        }

        if !launch_dic {
            let company = rows.iter().filter(|r| r.company.is_some()).count();
            let program_id = rows.iter().filter(|r| r.program_id.is_some()).count();
            println!("rows carrying Company {company}, ProgramId {program_id}");
            let mut codes: Vec<u32> = rows.iter().filter_map(|r| r.kind_code).collect();
            codes.sort_unstable();
            codes.dedup();
            println!("type codes seen {codes:?}");
        }
    }
}

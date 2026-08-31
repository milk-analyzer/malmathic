use mm_report::Report;

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../VM_TESTS");
    for name in ["test_4", "test_3", "test_2/winre", "test_2/live"] {
        let dir = root.join(name);
        let json_path = dir.join("report.json");
        let txt_path = dir.join("report.txt");
        let json = std::fs::read_to_string(&json_path).expect("report.json");
        let report: Report = serde_json::from_str(&json).expect("deserialises");

        let rendered = mm_report::text::render(&report);
        let on_disk = std::fs::read_to_string(&txt_path).expect("report.txt");
        let same_txt = rendered == on_disk || rendered.replace('\n', "\r\n") == on_disk;

        let reserialised = report.to_json();
        let same_json = reserialised.trim() == json.trim();

        println!(
            "{name:<14} report.txt {:<11} report.json {:<11} ({} bytes rendered, {} on disk)",
            if same_txt { "IDENTICAL" } else { "DIFFERS" },
            if same_json { "IDENTICAL" } else { "DIFFERS" },
            rendered.len(),
            on_disk.len()
        );
        if !same_txt {
            for (i, (a, b)) in rendered.lines().zip(on_disk.lines()).enumerate() {
                if a != b {
                    println!(
                        "   first difference at line {}:\n   rendered: {a:?}\n   on disk:  {b:?}",
                        i + 1
                    );
                    break;
                }
            }
        }
    }
}

use mm_report::Report;

fn main() {
    let path = std::env::args().nth(1).expect("usage: renderpinned <report.json>");
    let json = std::fs::read_to_string(&path).expect("report.json");
    let report: Report = serde_json::from_str(&json).expect("deserialises");
    print!("{}", mm_report::text::render(&report));
}

use mm_sign::pe::PeBytes;

fn main() {
    let Some(list) = std::env::args().nth(1) else {
        eprintln!("usage: truncated <file-with-one-path-per-line>");
        std::process::exit(2);
    };
    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };

    let (mut parsed, mut short, mut short_and_unsigned) = (0usize, 0usize, 0usize);
    for line in text.lines() {
        let path = line.trim().trim_start_matches('\u{feff}');
        if path.is_empty() {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Some(pe) = PeBytes::parse(&bytes) else { continue };
        parsed += 1;
        if pe.sections_fit() {
            continue;
        }
        short += 1;
        let unsigned = matches!(
            mm_sign::verify_embedded(&bytes, &mm_sign::TrustStore::embedded()),
            mm_sign::Verdict::Unsigned
        );
        if unsigned {
            short_and_unsigned += 1;
        }
        println!("{}{path}", if unsigned { "UNSIGNED  " } else { "          " });
    }
    println!(
        "\n{parsed} parsed, {short} shorter than their headers describe, \
         {short_and_unsigned} of those reported Unsigned"
    );
}

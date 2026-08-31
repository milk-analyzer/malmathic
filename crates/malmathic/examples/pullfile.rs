fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (image, path, out) = match args.as_slice() {
        [i, p, o] => (i.clone(), p.clone(), o.clone()),
        _ => {
            eprintln!("usage: pullfile <image> <\\volume\\relative\\path> <out>");
            std::process::exit(2);
        }
    };
    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(&image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(&image), *partition) {
            if volume.is_windows_install() {
                chosen = Some(volume);
                break;
            }
            if chosen.is_none() {
                chosen = Some(volume);
            }
        }
    }
    let Some(volume) = chosen else {
        eprintln!("no readable NTFS in {image}");
        std::process::exit(1);
    };
    match volume.read_capped(&path, 512 * 1024 * 1024) {
        Ok(bytes) => {
            std::fs::write(&out, &bytes).expect("writing");
            println!("{} bytes -> {out}", bytes.len());
        }
        Err(e) => {
            eprintln!("could not read {path}: {e}");
            std::process::exit(1);
        }
    }
}

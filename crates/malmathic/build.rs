use std::path::PathBuf;

const COMPANY: &str = "The malmathic authors";
const COPYRIGHT: &str = "Copyright (c) 2026 The malmathic authors";

const RT_VERSION: u16 = 16;
const LANGUAGE: u16 = 0x0409;
const CODEPAGE: u16 = 0x04B0;
const FIXED_BYTES: usize = 52;
const HEADER_BYTES: u32 = 32;
const MOVEABLE_AND_PURE: u16 = 0x0030;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let path = out.join("version.res");
    std::fs::write(&path, resource_file()).expect("the version resource must be writable");
    println!("cargo:rustc-link-arg-bins={}", path.display());
}

fn resource_file() -> Vec<u8> {
    let mut out = entry(0, 0, 0, 0, &[]);
    out.extend_from_slice(&entry(RT_VERSION, 1, MOVEABLE_AND_PURE, LANGUAGE, &version_info()));
    out
}

fn entry(type_id: u16, name_id: u16, flags: u16, language: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&HEADER_BYTES.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&type_id.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&name_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&language.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(data);
    pad(&mut out);
    out
}

fn version_info() -> Vec<u8> {
    let name = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let description = std::env::var("CARGO_PKG_DESCRIPTION").unwrap_or_default();
    let repository = std::env::var("CARGO_PKG_REPOSITORY").unwrap_or_default();
    let file_name = format!("{name}.exe");

    let fields = [
        ("Comments", repository.as_str()),
        ("CompanyName", COMPANY),
        ("FileDescription", description.as_str()),
        ("FileVersion", version.as_str()),
        ("InternalName", name.as_str()),
        ("LegalCopyright", COPYRIGHT),
        ("OriginalFilename", file_name.as_str()),
        ("ProductName", name.as_str()),
        ("ProductVersion", version.as_str()),
    ];
    let strings: Vec<Vec<u8>> = fields
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| text(key, value))
        .collect();

    let table = node(&format!("{LANGUAGE:04X}{CODEPAGE:04X}"), 1, &[], 0, &strings);
    let strings_for_windows = node("StringFileInfo", 1, &[], 0, std::slice::from_ref(&table));

    let mut translation = Vec::new();
    translation.extend_from_slice(&LANGUAGE.to_le_bytes());
    translation.extend_from_slice(&CODEPAGE.to_le_bytes());
    let spoken = node("Translation", 0, &translation, translation.len(), &[]);
    let languages = node("VarFileInfo", 1, &[], 0, std::slice::from_ref(&spoken));

    node("VS_VERSION_INFO", 0, &fixed(&version), FIXED_BYTES, &[strings_for_windows, languages])
}

fn fixed(version: &str) -> Vec<u8> {
    let mut parts = version.split('.').map(|p| p.parse::<u16>().unwrap_or(0));
    let major = u32::from(parts.next().unwrap_or(0));
    let minor = u32::from(parts.next().unwrap_or(0));
    let patch = u32::from(parts.next().unwrap_or(0));
    let most = (major << 16) | minor;
    let least = patch << 16;

    let mut out = Vec::with_capacity(FIXED_BYTES);
    for word in
        [0xFEEF_04BDu32, 0x0001_0000, most, least, most, least, 0x3F, 0, 0x0004_0004, 1, 0, 0, 0]
    {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn text(key: &str, value: &str) -> Vec<u8> {
    node(key, 1, &wide(value), value.encode_utf16().count() + 1, &[])
}

fn node(key: &str, kind: u16, value: &[u8], units: usize, children: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0, 0];
    out.extend_from_slice(&(units as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&wide(key));
    pad(&mut out);
    out.extend_from_slice(value);
    for child in children {
        pad(&mut out);
        out.extend_from_slice(child);
    }
    let length = u16::try_from(out.len()).expect("a version node stays under 64 KB");
    out[0..2].copy_from_slice(&length.to_le_bytes());
    out
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

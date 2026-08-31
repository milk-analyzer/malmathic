use std::fs::File;
use std::io::{Read, Result, Seek, SeekFrom};
use std::path::Path;

#[cfg(windows)]
const FILE_GENERIC_READ: u32 = 0x0012_0089;

#[derive(Debug)]
pub struct ReadOnlyFile(File);

impl ReadOnlyFile {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_GENERIC_READ)
                .open(path)
                .map(ReadOnlyFile)
        }
        #[cfg(not(windows))]
        {
            File::open(path).map(ReadOnlyFile)
        }
    }

    pub fn len(&self) -> Result<u64> {
        Ok(self.0.metadata()?.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    #[cfg(all(test, windows))]
    pub(crate) fn raw_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        self.0.as_raw_handle()
    }
}

impl Read for ReadOnlyFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for ReadOnlyFile {
    fn seek(&mut self, to: SeekFrom) -> Result<u64> {
        self.0.seek(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "mm-env-readonly-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).expect("a scratch file");
        path
    }

    #[test]
    fn it_reads_and_seeks_like_a_file() {
        let path = scratch("read.bin", b"0123456789");
        let mut f = ReadOnlyFile::open(&path).expect("opening");
        assert_eq!(f.len().unwrap(), 10);
        assert!(!f.is_empty().unwrap());

        let mut got = [0u8; 4];
        f.seek(SeekFrom::Start(6)).unwrap();
        f.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"6789");

        assert_eq!(f.len().unwrap(), 10);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_only_file_does_not_implement_write() {
        use std::marker::PhantomData;

        struct Probe<T>(PhantomData<T>);
        trait MaybeWrite {
            fn implements_write(&self) -> bool {
                false
            }
        }
        impl<T> MaybeWrite for Probe<T> {}
        impl<T: Write> Probe<T> {
            #[allow(dead_code)]
            fn implements_write(&self) -> bool {
                true
            }
        }

        assert!(
            Probe::<File>(PhantomData).implements_write(),
            "the probe is broken: std::fs::File is Write"
        );
        assert!(
            !Probe::<ReadOnlyFile>(PhantomData).implements_write(),
            "ReadOnlyFile has gained a Write impl — the image path can now write to evidence"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_operating_system_refuses_a_write_through_the_handle() {
        use std::mem::ManuallyDrop;
        use std::os::windows::io::FromRawHandle;

        let path = scratch("refuse.bin", b"EVIDENCE");
        let f = ReadOnlyFile::open(&path).expect("opening");

        let mut borrowed = ManuallyDrop::new(unsafe { File::from_raw_handle(f.raw_handle()) });
        let err = borrowed.write_all(b"XXXXXXXX").expect_err("the write must fail");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "expected access denied, got {err}"
        );

        drop(f);
        assert_eq!(std::fs::read(&path).unwrap(), b"EVIDENCE", "the file changed");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_is_an_error_rather_than_a_panic() {
        assert!(ReadOnlyFile::open(Path::new("no-such-file-at-all.bin")).is_err());
    }
}

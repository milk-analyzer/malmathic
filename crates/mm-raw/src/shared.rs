use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

struct Anchored<R> {
    reader: R,
    at: Option<u64>,
}

pub struct SharedReader<R> {
    inner: Arc<Mutex<Anchored<R>>>,
    position: u64,
}

impl<R> SharedReader<R> {
    pub fn new(reader: R) -> Self {
        SharedReader { inner: Arc::new(Mutex::new(Anchored { reader, at: None })), position: 0 }
    }

    fn lock(&self) -> MutexGuard<'_, Anchored<R>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<R> Clone for SharedReader<R> {
    fn clone(&self) -> Self {
        SharedReader { inner: Arc::clone(&self.inner), position: self.position }
    }
}

impl<R: Read + Seek> Read for SharedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut shared = self.lock();
        if shared.at != Some(self.position) {
            shared.at = None;
            let landed = shared.reader.seek(SeekFrom::Start(self.position))?;
            shared.at = Some(landed);
        }
        let read = match shared.reader.read(buf) {
            Ok(read) => read,
            Err(e) => {
                shared.at = None;
                return Err(e);
            }
        };
        shared.at = shared.at.map(|at| at.saturating_add(read as u64));
        drop(shared);
        self.position = self.position.saturating_add(read as u64);
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for SharedReader<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.position = match from {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => offset_by(self.position, delta)?,
            SeekFrom::End(delta) => {
                let mut shared = self.lock();
                shared.at = None;
                let end = shared.reader.seek(SeekFrom::End(delta))?;
                shared.at = Some(end);
                end
            }
        };
        Ok(self.position)
    }
}

fn offset_by(position: u64, delta: i64) -> io::Result<u64> {
    let target = i128::from(position) + i128::from(delta);
    u64::try_from(target)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes() -> SharedReader<io::Cursor<Vec<u8>>> {
        SharedReader::new(io::Cursor::new((0..=255u8).collect::<Vec<u8>>()))
    }

    #[test]
    fn two_handles_keep_their_own_positions() {
        let mut first = bytes();
        let mut second = first.clone();

        first.seek(SeekFrom::Start(10)).unwrap();
        second.seek(SeekFrom::Start(200)).unwrap();

        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        first.read_exact(&mut a).unwrap();
        second.read_exact(&mut b).unwrap();
        first.read_exact(&mut a[..2]).unwrap();

        assert_eq!(b, [200, 201, 202, 203]);
        assert_eq!(a[..2], [14, 15], "the other handle moved this one's position");
    }

    #[test]
    fn reading_past_the_end_stops() {
        let mut reader = bytes();
        reader.seek(SeekFrom::Start(1_000)).unwrap();
        assert_eq!(reader.read(&mut [0u8; 8]).unwrap(), 0);
    }

    #[test]
    fn seeking_before_the_start_is_refused() {
        let mut reader = bytes();
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
        assert_eq!(reader.stream_position().unwrap(), 0);
    }

    #[test]
    fn seeking_from_the_end_asks_the_reader() {
        let mut reader = bytes();
        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 254);
        let mut tail = [0u8; 2];
        reader.read_exact(&mut tail).unwrap();
        assert_eq!(tail, [254, 255]);
    }
}

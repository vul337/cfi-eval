use serde::Serialize;
use std::fs::File;
use std::ops::*;

#[derive(Debug, Default, Serialize)]
pub struct Ict {
    pub name: String,
    pub skipped: String,
    pub segments: Vec<Segment>,
    pub targets: Vec<Range<u64>>,
}

impl Ict {
    pub fn new(name: String) -> Self {
        Self {
            name,
            skipped: String::new(),
            targets: Default::default(),
            segments: vec![],
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Segment {
    pub start: u64,
    pub end: u64,
    pub perm: String,
    pub desc: String,
}

pub struct IctCollection {
    inner: Vec<Ict>,
    file: File,
}

impl Deref for IctCollection {
    type Target = Vec<Ict>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for IctCollection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for IctCollection {
    fn drop(&mut self) {
        log::info!(
            "exporting ICTs, {} actually verified",
            self.inner
                .iter()
                .filter(|ict| ict.skipped.is_empty())
                .count()
        );
        serde_json::to_writer(&mut self.file, &self.inner).expect("cannot write to file");
    }
}

impl IctCollection {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            file: File::create(path).expect("cannot open file"),
            inner: vec![],
        }
    }
}

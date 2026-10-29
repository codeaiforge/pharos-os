//! `cargo xtask store`: build and list writable-store images (storage.md
//! part 8), with the same `pharos-store` code the storage service runs.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use pharos_store::{BLOCK, Block, Device, IoError, Kind, Store};

use crate::Result;

/// A store image file as a block device.
pub struct FileDevice {
    file: File,
    blocks: u64,
}

impl FileDevice {
    /// Creates `path` (replacing it) with `blocks` zeroed blocks.
    pub fn create(path: &Path, blocks: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        file.set_len(blocks * BLOCK as u64)
            .map_err(|e| format!("cannot size {}: {e}", path.display()))?;
        Ok(Self { file, blocks })
    }

    /// Opens an existing image.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .len();
        Ok(Self {
            file,
            blocks: len / BLOCK as u64,
        })
    }
}

impl Device for FileDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }
    fn read(&mut self, block: u64, buf: &mut Block) -> std::result::Result<(), IoError> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK as u64))
            .and_then(|_| self.file.read_exact(buf))
            .map_err(|_| IoError)
    }
    fn write(&mut self, block: u64, buf: &Block) -> std::result::Result<(), IoError> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK as u64))
            .and_then(|_| self.file.write_all(buf))
            .map_err(|_| IoError)
    }
    fn flush(&mut self) -> std::result::Result<(), IoError> {
        self.file.sync_data().map_err(|_| IoError)
    }
}

/// Regular files under `dir` as (store path, host path), sorted. Links and
/// special files are refused, as for `fs build`.
fn files(dir: &Path, prefix: &str, out: &mut Vec<(String, std::path::PathBuf)>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: name is not UTF-8: {n:?}", dir.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_dir() {
            files(&path, &format!("{prefix}{name}/"), out)?;
        } else if kind.is_file() {
            out.push((format!("{prefix}{name}"), path));
        } else {
            return Err(format!(
                "{}: only regular files and directories can go into a store",
                path.display()
            ));
        }
    }
    out.sort();
    Ok(())
}

/// `cargo xtask store build <dir> <image> --blocks <n>`: a fresh store of
/// `blocks` blocks holding every regular file under `dir`.
pub fn build(dir: &Path, image: &Path, blocks: u64) -> Result<()> {
    let mut list = Vec::new();
    files(dir, "", &mut list)?;
    let mut store = Store::format(FileDevice::create(image, blocks)?)
        .map_err(|e| format!("{}: {e}", image.display()))?;
    for (path, host) in &list {
        let data = fs::read(host).map_err(|e| format!("cannot read {}: {e}", host.display()))?;
        store
            .write(path.as_bytes(), &data)
            .map_err(|e| format!("{path}: {e}"))?;
    }
    println!(
        "Store: {} ({} objects, {} of {blocks} blocks free)",
        image.display(),
        list.len(),
        store.free_blocks()
    );
    Ok(())
}

/// `cargo xtask store ls <image>`: mounts with the service's code, checks
/// every object, and lists them. Fails on the first problem.
pub fn ls(image: &Path) -> Result<()> {
    let mut store =
        Store::mount(FileDevice::open(image)?).map_err(|e| format!("{}: {e}", image.display()))?;
    println!(
        "generation {}, {} blocks free",
        store.generation(),
        store.free_blocks()
    );
    println!("{:<6}  {:>10}  {:>7}  path", "kind", "bytes", "records");
    let paths: Vec<Vec<u8>> = store.list(b"").map(<[u8]>::to_vec).collect();
    for path in paths {
        let name = String::from_utf8_lossy(&path).into_owned();
        let info = store.stat(&path).map_err(|e| format!("{name}: {e}"))?;
        match info.kind {
            Kind::File => {
                let mut data = vec![0u8; info.len as usize];
                store
                    .read(&path, 0, &mut data)
                    .map_err(|e| format!("{name}: {e}"))?;
                println!("{:<6}  {:>10}  {:>7}  {name}", "file", info.len, "-");
            }
            Kind::Stream => {
                store
                    .records(&path, |_| {})
                    .map_err(|e| format!("{name}: {e}"))?;
                println!(
                    "{:<6}  {:>10}  {:>7}  {name}",
                    "stream", info.len, info.records
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_ls_round_trips_and_detects_damage() {
        // Under target/, like every xtask output.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/xtask")
            .join(format!("store-test-{}", std::process::id()));
        let dir = root.join("in");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::write(dir.join("models/m.bin"), vec![7u8; 10_000]).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        let image = root.join("store.img");
        build(&dir, &image, 64).unwrap();
        ls(&image).unwrap();
        let mut store = Store::mount(FileDevice::open(&image).unwrap()).unwrap();
        let mut buf = vec![0u8; 10_000];
        assert_eq!(store.read(b"models/m.bin", 0, &mut buf), Ok(10_000));
        assert_eq!(store.list(b"").count(), 2);
        assert!(build(&dir, &image, 2).is_err(), "too small");
        // A store too small for its files is refused, not truncated.
        fs::write(dir.join("big"), vec![1u8; 100 * BLOCK]).unwrap();
        assert!(build(&dir, &image, 64).unwrap_err().contains("big"));
        // Damage both superblocks: ls reports it.
        build(&root.join("in/models"), &image, 16).unwrap();
        let mut bytes = fs::read(&image).unwrap();
        bytes[0] ^= 1;
        bytes[BLOCK] ^= 1;
        fs::write(&image, &bytes).unwrap();
        assert!(ls(&image).unwrap_err().contains("no valid superblock"));
        fs::remove_dir_all(&root).unwrap();
    }
}

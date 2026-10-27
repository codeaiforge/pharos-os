//! `cargo xtask fs`: build and list Pharos filesystem images (storage.md).

use std::fs;
use std::path::Path;

use pharos_fs::{Builder, Image};

use crate::Result;

/// Packs every regular file under `dir` into an image. Paths are relative
/// to `dir`, with `/` between components. Symbolic links and other special
/// files are refused, so the image matches what a reviewer sees.
pub fn pack(dir: &Path) -> Result<Vec<u8>> {
    let mut builder = Builder::new();
    add_dir(&mut builder, dir, "")?;
    builder
        .build()
        .map_err(|e| format!("cannot build an image from {}: {e}", dir.display()))
}

fn add_dir(builder: &mut Builder, dir: &Path, prefix: &str) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: name is not UTF-8: {n:?}", dir.display()))?;
        let image_path = format!("{prefix}{name}");
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if kind.is_dir() {
            add_dir(builder, &path, &format!("{image_path}/"))?;
        } else if kind.is_file() {
            let data =
                fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            builder
                .add(image_path.as_bytes(), &data)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        } else {
            return Err(format!(
                "{}: only regular files and directories can go into an image",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `cargo xtask fs build <dir> <image>`.
pub fn build(dir: &Path, image: &Path) -> Result<()> {
    let bytes = pack(dir)?;
    fs::write(image, &bytes).map_err(|e| format!("cannot write {}: {e}", image.display()))?;
    println!("Image: {} ({} bytes)", image.display(), bytes.len());
    Ok(())
}

/// `cargo xtask fs ls <image>`: mounts with the kernel's parser and lists
/// every file. Fails with the parser's reason on a corrupt image.
pub fn ls(image: &Path) -> Result<()> {
    let bytes = fs::read(image).map_err(|e| format!("cannot read {}: {e}", image.display()))?;
    let fs = Image::mount(&bytes[..]).map_err(|e| format!("{}: {e}", image.display()))?;
    println!("{:>10}  {:<8}  path", "size", "crc32");
    for file in fs.entries() {
        println!(
            "{:>10}  {:08x}  {}",
            file.size,
            file.crc,
            String::from_utf8_lossy(file.path)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_a_directory_tree() {
        let dir = std::env::temp_dir().join(format!("pharos-fs-pack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc/deep")).unwrap();
        fs::write(dir.join("etc/motd"), b"hello\n").unwrap();
        fs::write(dir.join("etc/deep/x"), b"").unwrap();
        fs::write(dir.join("top"), b"t").unwrap();
        let bytes = pack(&dir).unwrap();
        let image = Image::mount(&bytes[..]).unwrap();
        let paths: Vec<_> = image.entries().map(|f| f.path.to_vec()).collect();
        assert_eq!(paths, [&b"etc/deep/x"[..], b"etc/motd", b"top"]);
        assert_eq!(pack(&dir).unwrap(), bytes, "reproducible");

        fs::write(dir.join("bad name"), b"").unwrap();
        let err = pack(&dir).unwrap_err();
        assert!(
            err.contains("bad name") && err.contains("invalid path"),
            "{err}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use image::DynamicImage;
use tracing::{debug, info, warn};

const MAX_SIZE: (u32, u32) = (128, 128);

/// A thumbnail generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// filename of the image to resize
    image: std::path::PathBuf,

    /// Check that the thumbnail generated is the same as
    /// the one in the file provided
    #[arg(short, long)]
    check: Option<std::path::PathBuf>,

    /// Snapshot the program before generating the thumbnail
    #[arg(short, long)]
    snapshot: bool,

    /// Path to snapshot ELF
    #[arg(long, required_if_eq("snapshot", "true"))]
    elf: Option<std::path::PathBuf>,

    /// Path to snapshot metadata
    #[arg(long, required_if_eq("snapshot", "true"))]
    metadata: Option<std::path::PathBuf>,

    /// verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn resize(image_path: &std::path::Path) -> anyhow::Result<DynamicImage> {
    debug!("opening file {}", image_path.display());
    let img = image::io::Reader::open(image_path)
        .context("failed to load image")?
        .decode()
        .context("failed to decode image")?;
    let res = img.thumbnail(MAX_SIZE.0, MAX_SIZE.1);
    debug!("opened file {}", image_path.display());
    Ok(res)
}

fn equal(img: &DynamicImage, thumbnail_path: &std::path::Path) -> anyhow::Result<bool> {
    fn load(p: &std::path::Path) -> anyhow::Result<Vec<u8>> {
        let mut v = Vec::new();
        BufReader::new(File::open(p).context("failed to open file")?)
            .read_to_end(&mut v)
            .context("failed to read")?;
        Ok(v)
    }

    let tmp_path = [
        "/tmp",
        thumbnail_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("failed to get the file name"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("failed to convert the file name"))?,
    ]
    .iter()
    .collect::<PathBuf>();
    img.save(&tmp_path)
        .context("failed to write the thumbnail")?;

    Ok(load(thumbnail_path)? == load(&tmp_path)?)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    if args.snapshot {
        if snapshot::snapshot(&args.elf.unwrap(), &args.metadata.unwrap())? {
            info!("OK: snapshot done");
        } else {
            info!("OK: restored from snapshot");
        }
    }

    let thumbnail = resize(&args.image)?;

    if let Some(thumbnail_path) = args.check {
        debug!(
            "checking the thumbnail is not the same as the one in {}",
            thumbnail_path.display()
        );

        if equal(&thumbnail, &thumbnail_path)? {
            info!("OK: thumbnails are the same");
        } else {
            warn!("ERR: thumbnails are not the same");
        }
    } else {
        let name = args
            .image
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid file"))?;
        let parent = args
            .image
            .parent()
            .ok_or_else(|| anyhow::anyhow!("failed to find parent"))?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("failed to find parent"))?;
        let thumbnail_path = [
            parent,
            std::path::Path::new("thumbnails"),
            std::path::Path::new(name),
        ]
        .iter()
        .collect::<PathBuf>();

        debug!("saving thumbnail to {}", thumbnail_path.display());
        thumbnail
            .save(thumbnail_path)
            .context("failed to write the thumbnail")?;
    }

    Ok(())
}

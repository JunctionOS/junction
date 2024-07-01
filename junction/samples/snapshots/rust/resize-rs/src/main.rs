// use std::fs::File;
// use std::io::BufReader;
// use std::io::Read;
// use std::path::PathBuf;

use nix::sys::signal::{Signal, raise};

use anyhow::Context;
use clap::Parser;
use image::DynamicImage;
use tracing::{debug};
const MAX_SIZE: (u32, u32) = (128, 128);

/// A thumbnail generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// filename of the image to resize
    image: std::path::PathBuf,

    /// verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn resize(img: &image::DynamicImage) -> anyhow::Result<DynamicImage> {
    let res = img.thumbnail(MAX_SIZE.0, MAX_SIZE.1);
    Ok(res)
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

    let image_path: &_ = &args.image;
    debug!("opening file {}", image_path.display());
    let img = image::io::Reader::open(image_path)
        .context("failed to load image")?
        .decode()
        .context("failed to decode image")?;
    debug!("opened file {}", image_path.display());

    let mut _thumbnail = resize(&img)?;

    // warm up the function
    for _i in 0..5 {
        _thumbnail = resize(&img)?;
    }

    raise(Signal::SIGSTOP).unwrap();

    // run the function once more to profile 
    _thumbnail = resize(&img)?;

    println!("Done resizing!");

    Ok(())
}

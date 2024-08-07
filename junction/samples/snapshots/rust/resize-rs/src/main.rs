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

use nix::libc;
use std::io::{self, Write};
use std::time::Instant;

/// A thumbnail generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// filename of the image to resize
    image: std::path::PathBuf,

    prog_name: String,

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

    let mut prog_name = String::from("rust_resizer");
    if args.prog_name.len() > 0 {
        prog_name = args.prog_name;
    }

    let image_path: &_ = &args.image;
    debug!("opening file {}", image_path.display());
    let img = image::io::Reader::open(image_path)
        .context("failed to load image")?
        .decode()
        .context("failed to decode image")?;
    debug!("opened file {}", image_path.display());

    let mut times: Vec<u128> = Vec::with_capacity(5);
    let mut sizes: Vec<u32> = Vec::with_capacity(10);

    // warm up the function
    for _i in 0..5 {
        let start = Instant::now();
        let thumbnail = resize(&img)?;
        let duration = start.elapsed().as_micros();
        times.push(duration);
        sizes.push(thumbnail.width());
    }

    raise(Signal::SIGSTOP).unwrap();

    let start = Instant::now();

    // run the function once more to profile 
    let thumbnail = resize(&img)?;

    let duration = start.elapsed().as_micros();

    println!("Done resizing!");

    let mut result = String::from("DATA  {\"warmup\": [");

    for (i, warmup) in times.iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }
        result.push_str(&warmup.to_string());
    }

    result.push_str("], \"cold\": [");
    result.push_str(&duration.to_string());
    result.push_str("], \"program\": \"");
    result.push_str(&prog_name);
    result.push_str("\"}");

    println!("{}", result);

    io::stdout().flush().unwrap();

    unsafe {
        libc::syscall(libc::SYS_exit_group, 0);
    }

    sizes.push(thumbnail.width());

    for i in sizes {
        println!("{}", i);
    }


    Ok(())
}

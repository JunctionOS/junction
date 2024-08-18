// use std::fs::File;
// use std::io::BufReader;
// use std::io::Read;
// use std::path::PathBuf;

use std::env;
use nix::sys::signal::{Signal, raise};
use std::path::Path;
use std::fs::{File, OpenOptions};
use anyhow::Context;
use clap::Parser;
use image::DynamicImage;
use image::ImageOutputFormat;
use tracing::{debug};
const MAX_SIZE: (u32, u32) = (128, 128);

use nix::libc;
use std::io::{self, Write, BufRead, BufReader};
use std::time::Instant;

/// A thumbnail generator
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
struct Args {
    /// filename of the image to resize
    image: Option<std::path::PathBuf>,

    prog_name: Option<String>,

    /// verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Flag for the new version operation
    #[arg(long)]
    new_version: bool,
}

fn resize(img: &image::DynamicImage) -> anyhow::Result<DynamicImage> {
    let res = img.thumbnail(MAX_SIZE.0, MAX_SIZE.1);
    Ok(res)
}

fn trim_memory(pad: usize) {
    unsafe {
        libc::malloc_trim(pad);
    }
}

fn new_version() -> std::io::Result<()> {
    let path = Path::new("/serverless/chan0");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;

    let mut reader = BufReader::new(file);
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        let cmd = line.trim().to_string();

        if cmd == "SNAPSHOT_PREPARE" {
            trim_memory(0);
            reader.get_mut().write("OK".as_bytes())?;
            line.clear();
            continue;
        }

        let img = image::io::Reader::open(cmd).unwrap().decode().unwrap();
        let thumbnail = resize(&img).unwrap();
        let mut output_file = File::create("/tmp/img.png")?;
        thumbnail.write_to(&mut output_file, ImageOutputFormat::Png).unwrap();
        reader.get_mut().write("OK".as_bytes())?;
        line.clear();
    }

    Ok(())
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

    if args.new_version {
        new_version().unwrap();
        return Ok(());
    }

    let dont_stop = env::var("DONTSTOP").is_ok();
    let mut prog_name = String::from("rust_resizer");
    if let Some(pname) = args.prog_name {
        if pname.len() > 0 {
            prog_name = pname;
        }
    }

    let image_path: &_ = &args.image.unwrap();
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

    trim_memory(0);

    if !dont_stop {
        raise(Signal::SIGSTOP).unwrap();
    }

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

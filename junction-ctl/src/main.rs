use anyhow::Context;
use clap::{Parser, Subcommand};
use easy_repl::{command, CommandStatus, Repl};
use flatbuffers::FlatBufferBuilder;

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::control_request_generated::junction::ctl_schema::{
    finish_size_prefixed_request_buffer, GetStatsRequest, GetStatsRequestArgs, InnerRequest,
    Request, RequestArgs, RestoreRequest, RestoreRequestArgs, RunRequest, RunRequestArgs,
    SignalRequest, SignalRequestArgs, SnapshotRequest, SnapshotRequestArgs, StartTraceRequest,
    StartTraceRequestArgs, StopTraceRequest, StopTraceRequestArgs,
};

use self::control_response_generated::junction::ctl_schema::{
    size_prefixed_root_as_response, InnerResponse,
};

#[allow(dead_code, unused_imports)]
mod control_request_generated;

#[allow(dead_code, unused_imports)]
mod control_response_generated;

struct TracePoint {
    timestamp_us: u64,
    page_addr: usize,
}

impl std::fmt::Display for TracePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:>8}μs: {:#032x}", self.timestamp_us, self.page_addr)
    }
}

struct TraceReport {
    trace: Vec<TracePoint>,
}

enum GoodResponse {
    Ok,
    Stats,
    Trace(TraceReport),
    InvocationResult(String),
}

fn parse_signal(s: &str) -> Result<u64, String> {
    // accept numbers
    if let Ok(signo) = s.parse::<u64>() {
        return Ok(signo);
    }

    let signo = match s {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGILL" => 4,
        "SIGTRAP" => 5,
        "SIGABRT" => 6,
        "SIGIOT" => 6,
        "SIGBUS" => 7,
        "SIGFPE" => 8,
        "SIGKILL" => 9,
        "SIGUSR1" => 10,
        "SIGSEGV" => 11,
        "SIGUSR2" => 12,
        "SIGPIPE" => 13,
        "SIGALRM" => 14,
        "SIGTERM" => 15,
        "SIGSTKFLT" => 16,
        "SIGCHLD" => 17,
        "SIGCONT" => 18,
        "SIGSTOP" => 19,
        "SIGTSTP" => 20,
        "SIGTTIN" => 21,
        "SIGTTOU" => 22,
        "SIGURG" => 23,
        "SIGXCPU" => 24,
        "SIGXFSZ" => 25,
        "SIGVTALRM" => 26,
        "SIGPROF" => 27,
        "SIGWINCH" => 28,
        "SIGIO" => 29,
        unknown => {
            return Err(format!("unknown singal: {}", unknown));
        }
    };

    Ok(signo)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    hostname: String,

    #[arg(short, long, default_value_t = 42, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        argv: Vec<String>,
    },
    RunAux {
        bin: String,
        argv: Vec<String>,
    },
    Snapshot {
        pid: u64,
        snapshot_path: String,
        elf_path: String,
    },
    Restore {
        snapshot_path: String,
        elf_path: String,
        args: String,
    },
    StartTrace {
        pid: u64,
    },
    StopTrace {
        pid: u64,
    },
    Signal {
        pid: u64,

        #[arg(value_parser = parse_signal)]
        signal: u64,
    },
    GetStats,
}

fn await_response(mut stream: TcpStream) -> anyhow::Result<GoodResponse> {
    let mut size_buf = [0; std::mem::size_of::<u32>()];
    stream
        .read_exact(&mut size_buf)
        .context("failed to read size")?;

    let len: u32 = unsafe { flatbuffers::read_scalar(&size_buf[0..std::mem::size_of::<u32>()]) };

    let mut vec = Vec::with_capacity(std::mem::size_of::<u32>() + len as usize);
    for byte in size_buf {
        vec.push(byte);
    }

    let mut take = stream.take(len as u64);
    take.read_to_end(&mut vec)
        .context("failed to read rest of the object")?;

    let resp = size_prefixed_root_as_response(&vec).context("failed to deserialize response")?;

    match resp.inner_type() {
        InnerResponse::error => Err(anyhow::anyhow!(
            "remote error on server: {}",
            resp.inner_as_error()
                .expect("we checked that the response was an error")
                .message()
                .unwrap_or("<error message not found>")
        )),
        InnerResponse::genericSuccess => Ok(GoodResponse::Ok),
        InnerResponse::getStats => Ok(GoodResponse::Stats),
        InnerResponse::traceReport => {
            let trace_report = resp
                .inner_as_trace_report()
                .expect("we checked that the response was a trace report");
            let accessed = trace_report
                .accessed_us()
                .ok_or_else(|| anyhow::anyhow!("accessed trace not set in trace report"))?;
            let min_ts = accessed
                .iter()
                .map(|tp| tp.timestamp_us())
                .min()
                .unwrap_or(0);
            let mut trace = accessed
                .iter()
                .map(|tp| TracePoint {
                    timestamp_us: tp.timestamp_us() - min_ts,
                    page_addr: tp.accessed_location() as usize,
                })
                .collect::<Vec<TracePoint>>();

            trace.sort_by_key(|tp| tp.timestamp_us);

            Ok(GoodResponse::Trace(TraceReport { trace }))
        }
        InnerResponse::invokeResponse => {
            let result = resp
                .inner_as_invoke_response()
                .expect("we checked already")
                .message()
                .unwrap_or("<error message not found>");
            Ok(GoodResponse::InvocationResult(result.to_string()))
        }
        InnerResponse::NONE | _ => Err(anyhow::anyhow!("invalid response")),
    }
}

fn cli(uri: &str) -> anyhow::Result<()> {
    let mut repl = Repl::builder()
        .add(
            "run",
            easy_repl::Command {
                description: "run a process".into(),
                args_info: vec!["argv: Vec<String>".into()],
                handler: Box::new(|argv| {
                    run(uri, argv)?;
                    Ok(CommandStatus::Done)
                })
            },
        )
        .add(
            "run_aux",
            easy_repl::Command {
                description: "run auxiliary process".into(),
                args_info: vec!["argv: Vec<String>".into()],
                handler: Box::new(|argv: &[&str]| {
                    if argv.len() < 2 {
                        return Err(anyhow::anyhow!("Missing arguments: bin and argv"));
                    }
                    // Call run_aux with the arguments
                    run_aux(uri, argv[0], &argv[1..])?;
                    Ok(CommandStatus::Done)
                }),
            }
        )
        .add(
            "snapshot",
            command! {
                "snapshot a process",
                (pid: u64, snapshot_path: String, elf_path: String) => |pid, snapshot_path: String, elf_path: String| {
                    snapshot(uri, pid, snapshot_path.as_str(), elf_path.as_str())?;
                    Ok(CommandStatus::Done)
                }
            },
        )
        .add(
            "restore",
            command! {
                "restore a process",
                (snapshot_path: String, elf_path: String, args: String) => |snapshot_path: String, elf_path: String, args: String| {
                    restore(uri, snapshot_path.as_str(), elf_path.as_str(), args.as_str())?;
                    Ok(CommandStatus::Done)
                }
            },
        )
        .add(
            "start-trace",
            command! {
                "start tracing a process",
                (pid: u64) => |pid| {
                    start_trace(uri, pid)?;
                    Ok(CommandStatus::Done)
                }
            },
        )
        .add(
            "stop-trace",
            command! {
                "stop tracing a process",
                (pid: u64) => |pid| {
                    stop_trace(uri, pid)?;
                    Ok(CommandStatus::Done)
                }
            },
        )
        .add(
            "signal",
            command! {
                "signal a process",
                (pid: u64, sig_str: String) => |pid, sig_str: String| {
                    match parse_signal(sig_str.as_str()) {
                        Ok(signo) => {
                            signal(uri, pid, signo)?;
                            Ok(CommandStatus::Done)
                        }
                        Err(e) => {
                            Err(anyhow::anyhow!("failed to parse signal: {}", e))
                        }
                    }
                }
            },
        )
        .add(
            "get-stats",
            command! {
                "get statistics on the process",
                () => || {
                    get_stats(uri)?;
                    Ok(CommandStatus::Done)
                }
            },
        )
        .build()
        .context("Failed to create repl")?;

    repl.run()
}

fn run(uri: &str, argv: &[&str]) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();

    let argv_fb = argv
        .iter()
        .map(|s| fbb.create_string(s))
        .collect::<Vec<_>>();

    let bin = Some(fbb.create_string(argv[0]));

    let argv = Some(fbb.create_vector_from_iter(argv_fb.into_iter()));

    let run_req = RunRequest::create(
        &mut fbb,
        &RunRequestArgs {
            bin,
            argv,
            is_init: true,
        },
    );

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::run,
            inner: Some(run_req.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);

    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write run request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}

fn run_aux(uri: &str, bin: &str, argv: &[&str]) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();

    let bin = Some(fbb.create_string(bin));
    let argv_fb = argv
        .iter()
        .map(|s| fbb.create_string(s))
        .collect::<Vec<_>>();
    let argv = Some(fbb.create_vector_from_iter(argv_fb.into_iter()));

    let run_req = RunRequest::create(
        &mut fbb,
        &RunRequestArgs {
            bin,
            argv,
            is_init: false,
        },
    );

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::run,
            inner: Some(run_req.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);

    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write run request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}

fn snapshot(uri: &str, pid: u64, snapshot_path: &str, elf_path: &str) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let snapshot_path = Some(fbb.create_string(snapshot_path));
    let elf_path = Some(fbb.create_string(elf_path));
    let snap_req = SnapshotRequest::create(
        &mut fbb,
        &SnapshotRequestArgs {
            pid,
            snapshot_path,
            elf_path,
        },
    );

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::snapshot,
            inner: Some(snap_req.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}

fn restore(uri: &str, snapshot_path: &str, elf_path: &str, args: &str) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let snapshot_path = Some(fbb.create_string(snapshot_path));
    let elf_path = Some(fbb.create_string(elf_path));
    let argument = Some(fbb.create_string(args));
    let restore_req = RestoreRequest::create(
        &mut fbb,
        &RestoreRequestArgs {
            snapshot_path,
            elf_path,
            chan: 0,
            argument,
        },
    );

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::restore,
            inner: Some(restore_req.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        GoodResponse::InvocationResult(s) => {
            println!("Got response {}", s);
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}

fn start_trace(uri: &str, pid: u64) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let inner = StartTraceRequest::create(&mut fbb, &StartTraceRequestArgs { pid });

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::startTrace,
            inner: Some(inner.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}
fn stop_trace(uri: &str, pid: u64) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let inner = StopTraceRequest::create(&mut fbb, &StopTraceRequestArgs { pid });

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::stopTrace,
            inner: Some(inner.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Err(anyhow::anyhow!(
            "mismatched response (expected Trace, got SuccessResponse)"
        )),
        GoodResponse::Trace(report) => {
            for t in report.trace {
                println!("{}", t);
            }
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse or Trace)"
        )),
    }
}
fn signal(uri: &str, pid: u64, signo: u64) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let inner = SignalRequest::create(&mut fbb, &SignalRequestArgs { pid, signo });

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::signal,
            inner: Some(inner.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Ok => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected SuccessResponse)"
        )),
    }
}
fn get_stats(uri: &str) -> anyhow::Result<()> {
    let mut fbb = FlatBufferBuilder::new();
    let inner = GetStatsRequest::create(&mut fbb, &GetStatsRequestArgs {});

    let req = Request::create(
        &mut fbb,
        &RequestArgs {
            inner_type: InnerRequest::getStats,
            inner: Some(inner.as_union_value()),
        },
    );

    finish_size_prefixed_request_buffer(&mut fbb, req);
    let mut stream = get_stream(uri)?;
    stream
        .write_all(fbb.finished_data())
        .context("failed to write snapshot request")?;

    match await_response(stream)? {
        GoodResponse::Stats => Ok(()),
        _ => Err(anyhow::anyhow!(
            "mismatched response (expected GetStatsResponse)"
        )),
    }
}

fn get_stream(uri: &str) -> anyhow::Result<TcpStream> {
    TcpStream::connect(uri).context(format!("failed to connect to {}", uri))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let uri = format!("{}:{}", args.hostname, args.port);

    match args.command {
        None => cli(uri.as_str()),
        Some(Command::Run { argv }) => {
            let args = argv.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
            run(uri.as_str(), args.as_slice())
        }
        Some(Command::RunAux { bin, argv }) => {
            let args = argv.iter().map(|x| x.as_str()).collect::<Vec<&str>>();
            run_aux(uri.as_str(), bin.as_str(), args.as_slice())
        }
        Some(Command::Snapshot {
            pid,
            snapshot_path,
            elf_path,
        }) => snapshot(uri.as_str(), pid, snapshot_path.as_str(), elf_path.as_str()),
        Some(Command::Restore {
            snapshot_path,
            elf_path,
            args,
        }) => restore(
            uri.as_str(),
            snapshot_path.as_str(),
            elf_path.as_str(),
            args.as_str(),
        ),
        Some(Command::StartTrace { pid }) => start_trace(uri.as_str(), pid),
        Some(Command::StopTrace { pid }) => stop_trace(uri.as_str(), pid),
        Some(Command::Signal { pid, signal: signo }) => signal(uri.as_str(), pid, signo),
        Some(Command::GetStats) => get_stats(uri.as_str()),
    }
}

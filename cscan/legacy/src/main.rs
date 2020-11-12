mod binary;
mod debugger;
mod disasm;
mod tester;

use debugger::Debugger;
use humansize::{file_size_opts::BINARY, FileSize};
use log::*;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Range;
use std::time::Instant;
use structopt::StructOpt;
use tester::*;

#[derive(Debug, Default, Serialize)]
struct IctTestResult {
    name: String,
    skipped: bool,
    segments: Vec<Segment>,
    targets: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
struct Segment {
    start: u64,
    end: u64,
    perm: String,
    desc: String,
}

#[derive(Debug, StructOpt)]
struct Opt {
    /// The index for ICT where fuzzing starts. ICTs before are ignored.
    #[structopt(long, default_value = "0")]
    start: u64,

    /// The index for ICT where fuzzing ends. ICTs equal or greater are ignored.
    #[structopt(long)]
    end: Option<u64>,

    /// The file name to export.
    #[structopt(long, name = "filename")]
    export: String,

    /// Specify the CFI system to test.
    #[structopt(long)]
    mode: String,

    /// Arguments to run the target program.
    #[structopt(parse(from_os_str), set(structopt::clap::ArgSettings::Last))]
    args: Vec<OsString>,
}

fn cfifuzz(tester: &mut dyn CfiTester, range: Range<u64>) -> Vec<IctTestResult> {
    let mut icts = vec![];
    let mut tested = HashSet::<String>::default();
    while let Some((name, ranges)) = tester.advance_ict() {
        // Insert a new entry into result.
        let ict = IctTestResult {
            name,
            skipped: true,
            targets: Default::default(),
            segments: vec![],
        };
        icts.push(ict);
        let ict_index = icts.len() - 1;
        let ict = &mut icts[ict_index];
        let ict_index = ict_index as u64;
        let is_tested = !tested.insert(ict.name.clone());

        // Skip maybe.
        if ict_index >= range.end {
            info!("skip (after) ict #{}: {}", ict_index, ict.name);
            break;
        }
        if is_tested {
            info!("skip (dup) ict #{}: {}", ict_index, ict.name);
            continue;
        }
        if ict_index < range.start {
            info!("skip (below) ict #{}: {}", ict_index, ict.name);
            continue;
        }

        // Prepare for fuzz.
        ict.skipped = false;
        ict.segments = tester
            .vmmap()
            .drain(..)
            .map(|segment| Segment {
                start: segment.address.0,
                end: segment.address.1,
                perm: segment.perms,
                desc: format!("{:?}", segment.pathname),
            })
            .collect();
        let total_targets: u64 = ranges.iter().map(|range| range.end - range.start).sum();
        let total = total_targets.file_size(BINARY).unwrap();
        info!("test ict #{}: {}, total = {}", ict_index, ict.name, total);

        let mut total_runs = 0u32;
        let mut last_runs = 0u32;
        let mut started = Instant::now();
        for range in ranges {
            for target in range {
                let jump_allowed = tester.run_test(target);

                if jump_allowed {
                    trace!("allowed target {:#x}", &target);
                    ict.targets.insert(format!("{:#x}", &target));
                } else {
                    trace!("denied target {:#x}", target);
                }

                total_runs += 1;
                last_runs += 1;
                if total_runs % 4096 == 0 {
                    let duration = started.elapsed().as_secs_f64();
                    if duration > 2.0 {
                        let exec_per_sec = last_runs as f64 / duration;
                        debug!(
                            "progress: {:.2}% ({} / {}), {}/s",
                            (total_runs as f64 / total_targets as f64 * 100.0),
                            total_runs,
                            total_targets,
                            (exec_per_sec as u64).file_size(BINARY).unwrap(),
                        );
                        started = Instant::now();
                        last_runs = 0;
                    }
                }
            }
        }

        info!(
            "allow rate of ict #{}: {:.2}% ({} / {})",
            ict_index,
            (ict.targets.len() as f64 / total_targets as f64) * 100.0,
            ict.targets.len(),
            total_targets,
        );
    }

    icts
}

const MODES: &[(&str, fn(debugger::Debugger) -> Box<dyn CfiTester>)] = &[
    ("lockdown", LockdownTester::new),
    ("llvm", LlvmTester::new),
    ("tsx-rtm", TsxTester::new_rtm),
    ("tsx-hle", TsxTester::new_hle),
    ("cfi-lb", CfiLbTester::new_cfilb),
    ("os-cfi", CfiLbTester::new_oscfi),
    ("mcfi", MCfiTester::new),
];

fn main() {
    env_logger::builder().init();
    let opt = Opt::from_args();
    let end = opt.end.unwrap_or(u64::max_value());

    info!("running {:?}", opt.args);
    let debugger = Debugger::new(&opt.args[..]);
    let tester = MODES
        .iter()
        .find(|(name, _func)| name == &opt.mode.as_str())
        .map(|(_name, func)| func(debugger));
    let mut tester = match tester {
        Some(tester) => tester,
        None => {
            let supported: Vec<_> = MODES.iter().map(|(name, _func)| name).collect();
            eprintln!("list of supported CFI system: {:?}", supported);
            panic!("unsupported CFI system ({:?})", opt.mode);
        }
    };
    let icts = cfifuzz(&mut *tester, opt.start..end);

    log::info!(
        "exporting ICTs, {} actually fuzzed",
        icts.iter().filter(|ict| !ict.skipped).count()
    );
    let file = File::create(&opt.export).expect("cannot open file");
    serde_json::to_writer_pretty(file, &icts).expect("cannot write to file");

    log::info!("bye");
}

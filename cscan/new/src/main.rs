mod binary;
mod debugger;
mod disasm;
mod export;
mod verifier;
mod range_set;

use debugger::Debugger;
use dfuzz_os::process::*;
use log::*;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt::Debug;
use structopt::StructOpt;
use verifier::CfiVerifier;

#[derive(Debug, StructOpt)]
struct Opt {
    /// The index for ICT where fuzzing starts. ICTs before are ignored.
    #[structopt(long, default_value = "0")]
    start: u64,

    /// The index for ICT where fuzzing ends. ICTs equal or greater are ignored.
    #[structopt(long, default_value = "18446744073709551615")]
    end: u64,

    /// The file name to export.
    #[structopt(long, name = "filename")]
    export: String,

    /// Specify the CFI system to test.
    #[structopt(long)]
    mode: String,

    /// Arguments to run the target program.
    #[structopt(parse(from_os_str), set(structopt::clap::ArgSettings::Last))]
    args: Vec<OsString>,

    /// Make the ICT oneshot, i.e. remove its breakpoint after testing.
    /// Accelerates the testing at the cost of losing contextual information and
    /// incorrect ICT numbering.
    #[structopt(long)]
    oneshot: bool,

    /// Skip testing the ICTs.
    #[structopt(long)]
    ignore: Vec<u64>,
}

fn run(
    mut dbg: Debugger,
    mut verifier: Box<dyn CfiVerifier>,
    icts: &mut export::IctCollection,
    opt: &Opt,
) {
    let mut tested_icts = HashSet::<String>::default();
    let ignore: HashSet<_> = opt.ignore.iter().collect();
    loop {
        let regs = match dbg.next_event() {
            Ok(regs) => regs,
            Err(event) => {
                if let EventKind::Terminated(TerminateReason::Exit { status: 0 }) = event {
                    info!("normal exit (status = 0)");
                } else {
                    warn!("abnormal exit: {:?}", event);
                    dbg.let_it_go();
                }
                break;
            }
        };

        // Insert a new entry into result.
        let ict_index = icts.len() as u64;
        icts.push(export::Ict::new(verifier.identify_ict(&mut dbg, &regs)));
        let ict = icts.iter_mut().last().unwrap();
        let is_tested = !tested_icts.insert(ict.name.clone());

        if opt.oneshot {
            const NOP: &[u8] = &[0x90];
            dbg.process
                .trace_write_memory_force(regs.rip - 1, NOP)
                .unwrap();
        }
        // Skip maybe.
        if ict_index >= opt.end {
            ict.skipped = "above".to_string();
            info!("exit after ict #{}: {}", ict_index, ict.name);
            break;
        }
        if ignore.contains(&ict_index) {
            ict.skipped = "ignore".to_string();
            info!("skip ({}) ict #{}: {}", ict.skipped, ict_index, ict.name);
            continue;
        }
        if is_tested {
            ict.skipped = "dup".to_string();
            info!("skip ({}) ict #{}: {}", ict.skipped, ict_index, ict.name);
            continue;
        }
        if ict_index < opt.start {
            ict.skipped = "below".to_string();
            info!("skip ({}) ict #{}: {}", ict.skipped, ict_index, ict.name);
            continue;
        }

        // Prepare for verification.
        ict.segments = dbg
            .process
            .to_procfs()
            .unwrap()
            .maps()
            .unwrap()
            .drain(..)
            .map(|segment| export::Segment {
                start: segment.address.0,
                end: segment.address.1,
                perm: segment.perms,
                desc: format!("{:?}", segment.pathname),
            })
            .collect();

        // Run verification.
        info!("ict #{}: {}, verifying", ict_index, ict.name);
        ict.targets = verifier.verify_ict(&mut dbg, &regs).into_ranges();

        // Cleanup.
        dbg.set_regs(&regs);
    }
}

fn main() {
    let env = env_logger::Env::default().default_filter_or("info,cfifuzz::verifier=trace");
    env_logger::from_env(env).init();

    let opt = Opt::from_args();
    let mut icts = export::IctCollection::new(&std::path::PathBuf::from(opt.export.clone()));
    if opt.oneshot {
        warn!(
            "oneshot mode enabled: contextual information may be lost; ict counting is different from non-oneshot mode"
        );
    }

    info!("running {:?}", opt.args);
    let mut dbg = Debugger::new(&opt.args[..]);
    let verifier: Box<dyn CfiVerifier> = match opt.mode.as_str() {
        "cfi-lb" => Box::new(verifier::CfiLbVerifier::new(&mut dbg)),
        "mcfi" => Box::new(verifier::MCfiVerifier::new(&mut dbg)),
        "llvm" => Box::new(verifier::LlvmVerifier::new(&mut dbg)),
        _ => panic!("unsupported CFI system ({:?})", opt.mode),
    };

    run(dbg, verifier, &mut icts, &opt);
    drop(icts);
    info!("bye");
}

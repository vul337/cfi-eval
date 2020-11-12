# CScan: Scan Your CFI's Feasible Targets

This is the CScan part of source code of our CCS'20 paper "Finding Cracks in
Shields: On the Security of Control Flow Integrity Mechanisms".

To use CScan, you need to build the binary for evaluation with the target CFI
and our [debug pass](./DebugPass). The debug pass inserts markers at compile
time for the dynamic part of CScan. See individual readmes for implementation
details.

The dynamic part of CScan has two versions: `new` and `legacy`.
The new version is better organized and rich in feature, but supports less
modes. We recommend this version as the base for further developments. The
legacy version supports more CFIs (see `main.rs`).

New version:

```rust
    let verifier: Box<dyn CfiVerifier> = match opt.mode.as_str() {
        "cfi-lb" => Box::new(verifier::CfiLbVerifier::new(&mut dbg)),
        "mcfi" => Box::new(verifier::MCfiVerifier::new(&mut dbg)),
        "llvm" => Box::new(verifier::LlvmVerifier::new(&mut dbg)),
        _ => panic!("unsupported CFI system ({:?})", opt.mode),
    };
```

Legacy version:

```rust
const MODES: &[(&str, fn(debugger::Debugger) -> Box<dyn CfiTester>)] = &[
    ("lockdown", LockdownTester::new),
    ("llvm", LlvmTester::new),
    ("tsx-rtm", TsxTester::new_rtm),
    ("tsx-hle", TsxTester::new_hle),
    ("cfi-lb", CfiLbTester::new_cfilb),
    ("os-cfi", CfiLbTester::new_oscfi),
    ("mcfi", MCfiTester::new),
];
```


## Usage

```bash
export RUST_LOG=info,cfifuzz::tester=trace # Show logs
cargo run --release -- --export=llvm.json --mode=llvm -- ./bin/astar-llvm
```

Use the `--help` option to view specific usage.

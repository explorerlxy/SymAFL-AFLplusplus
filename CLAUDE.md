# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the SymAFL-modified AFL++ subtree.

## Scope

This is a modified AFL++ repository. SymAFL adds a Z3-backed **Path Constraint Binary Tree (PCBT)** that pre-screens mutated inputs before expensive concrete execution. For the complete cross-component workflow, see [`../CLAUDE.md`](../CLAUDE.md); for runtime SHM behavior, see [`../symcc/CLAUDE.md`](../symcc/CLAUDE.md).

## SymAFL PCBT Architecture

| Responsibility | Files |
|---|---|
| PCBT implementation: Z3 constraints, `CheckInput`, trace insertion, rendering, stats | `src/PathConTree.cpp` |
| C-facing PCBT API used from AFL++ C sources | `include/PathConTree.hpp` |
| `-K[initDecCnt]` parsing, `symcc_mode`, tree creation | `src/afl-fuzz.c` |
| Candidate pre-screening before target execution; queue/depth SHM values | `src/afl-fuzz-run.c` |
| Accepted-seed handling, symbolic trace insertion, PCBT snapshots | `src/afl-fuzz-bitmap.c` |
| Initial queue handling, reload, and SHM setup | `src/afl-fuzz-init.c` |
| SymAFL state fields and statistics | `include/afl-fuzz.h` |
| Custom SHM environment variable names | `include/config.h` |

### PCBT Lifecycle

1. `afl-fuzz -K[initDecCnt]` enables `symcc_mode` and creates a PCBT. The optional initial symbolic-declaration count defaults to `1024`. `-K` is custom and is not listed by the ordinary AFL++ help output.
2. During mutation, `path_con_tree_check_input()` runs before concrete execution. It returns a positive tree depth for a candidate that can open a new branch, `-1` when no new branch is available, and `-2` when the tree is exhausted.
3. For a candidate selected for execution, AFL++ passes queue entry ID and insertion depth through shared memory. The QSYM runtime produces an incremental SMT trace.
4. `save_if_interesting()` retains coverage-interesting cases and calls `path_con_tree_insert_trace()` to extend the tree. Rejected cases must not be treated as normal concretely executed candidates.
5. SymAFL-v1 has no focus mode: the PCBT is used exclusively for pre-execution candidate screening. Candidates that pass `CheckInput` execute once in concolic mode (`*__symbolic = 1` is set before their fork and reset afterwards). Coverage-gaining executions are queued and their `.pct` trace is inserted; executions without coverage gain increment the target branch's low-value counter and may mark that branch as fully explored after the configured threshold.
6. Screening counters (`pcbt_candidate_cnt`, `pcbt_admitted_cnt`, `pcbt_rejected_cnt`, `pcbt_exhausted_cnt`, `pcbt_concolic_exec_cnt/tm`, `pcbt_trace_insert_cnt`, `pcbt_no_cov_gain_cnt`, and `pcbt_saturated_branch_cnt`) are written to `sym_mode_stats`. Candidate throughput is `pcbt_candidate_cnt / pcbt_wall_tm` and includes rejected candidates; `fsrv.total_execs` must not be used for it.

`PathConTree.hpp` relies on inclusion through `afl-fuzz.h` for `afl_state_t` and `queue_entry` declarations. Preserve that include-order assumption when changing the API.

## Build and Test

Run commands from this directory. `GNUmakefile` builds `libpathcontree.so` with Z3 and links `afl-fuzz` against `-lpathcontree`, `-lz3`, and an `$ORIGIN` runtime path.

```bash
# Full AFL++ build, including the PCBT shared library
gmake all

# Build only source-mode AFL++ components
gmake source-only

# Upstream AFL++ test suite and focused unit tests
gmake tests
gmake unit

# Formatting and cleanup
gmake code-format
gmake clean
```

Z3 headers and libraries must be available to build `libpathcontree.so`.

The SymAFL end-to-end fixtures (formerly `test/symccTest/`) have moved out of this repository to the SymAFL integration repository under `tests/fixtures/`; they are **not** exercised by the normal `gmake tests` target. Use an end-to-end run to validate SymAFL behavior:

```bash
export SYMAFL_ROOT=/media/hahafish/Data/ForUbuntu/SymAFL
# /home/hahafish/SymAFL used by legacy scripts is a symlink to this checkout.
source "$SYMAFL_ROOT/symafl-env.sh"

symafl-build --symcc target.c -o target
symafl-fuzz ./target seeds /tmp/symafl-output
```

Confirm that the output queue receives `.pct-*` files, PCBT snapshots, and `sym_mode_stats`; see the artifact contract below.

## Runtime Artifact Contract

The QSYM runtime consumes the normal AFL coverage SHM plus these custom environment-variable-backed SysV SHM segments:

| Environment variable | Purpose |
|---|---|
| `__AFL_SHM_SYMBOLIC_ENV_ID` | Execution mode: `0` concrete, `1` symbolic |
| `__AFL_SHM_OUTDIR_ENV_ID` | AFL output directory |
| `__AFL_SHM_QUEUE_ENTRY_ID` | Current queue entry ID |
| `__AFL_SHM_INSERT_DEPTH__ID` | First newly persisted constraint depth; spelling is intentional |

Expected output artifacts:

- `output/queue/.pct-XXXXXX`: incremental SMT constraints for a retained execution.
- `output/queue/.PathConTree-*.dot` and `.png`: PCBT snapshots/final rendering.
- `output/sym_mode_stats`: PCBT and execution statistics.

Keep these names aligned with `../symcc/runtime/src/backends/qsym/Runtime.cpp`. PCBT mode requires output storage on ext4/xfs or another filesystem that supports AFL++ queue names containing `:`; do not use NTFS-backed output directories.

## PCBT Tuning and Invariants

`PathConTree.cpp` accepts these environment variables:

| Variable | Default | Effect |
|---|---:|---|
| `MAX_ALLOWED_RIGHT_CHILD_CNT` | 128 | Limit repeated attempts at an unexplored negated branch |
| `MAX_ALLOWED_SOLVER_TIMEOUT` | 1000 ms | Z3 timeout for PCBT checks |

Do not change the PCBT algorithm, runtime trace format, or SHM names independently: the matching compiler/runtime behavior is split across [`../RSan/CLAUDE.md`](../RSan/CLAUDE.md) and [`../symcc/CLAUDE.md`](../symcc/CLAUDE.md).

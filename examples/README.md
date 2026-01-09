# IDA Domain Scripting Exercises

This folder contains 20 reverse engineering exercises for evaluating IDAPython scripting skills. Each exercise focuses on a specific analysis technique commonly needed in real-world binary analysis.

## Exercise Categories

| Category | Exercises | Focus |
|----------|-----------|-------|
| **A. Triage & Global Mapping** | 01-04 | Bulk classification, callgraph analysis, thunk resolution, import mapping |
| **B. Strings & Config Recovery** | 05-08 | Encrypted strings, config carving, string provenance, command dispatch |
| **C. Function Boundaries & Types** | 09-12 | Prototype reconstruction, chunk repair, vtables, variable renaming |
| **D. Control-Flow Obfuscation** | 13-15 | Flattening detection, opaque predicates, junk block cleanup |
| **E. Patch Planning & Workflow** | 16-18 | License checks, hook surfaces, SARIF export |
| **F. Advanced** | 19-20 | Symbolic propagation, scalable annotation |

## Exercise Status

### Successfully Generated (16 exercises)

| # | Exercise | Language | Description |
|---|----------|----------|-------------|
| 01 | `01_auto_tag_function_roles` | Zig | 60+ functions across crypto/compression/parsing/allocator/logging categories. Stripped binary. |
| 02 | `02_callgraph_hotspot_ranking` | Zig | 217 functions with central dispatchers, multiple call layers, mutual recursion patterns. |
| 03 | `03_thunk_forest_deobfuscation` | Zig | 36+ thunk functions with 4-level chains, GOT-style indirect jumps, partial thunks. |
| 04 | `04_cross_module_import_map` | Zig | 170+ imports (libc, network, crypto, file I/O) plus dlsym-based dynamic resolution patterns. |
| 05 | `05_encrypted_string_recovery` | Zig | 35 obfuscated strings using XOR (single/rolling), ADD/SUB encoding, stack construction. |
| 06 | `06_config_structure_carving` | Zig | 676-byte embedded config blob with nested structures, mixed field types, high-entropy regions. |
| 07 | `07_string_provenance_report` | Zig | 118+ interesting strings (URLs, IPs, registry keys, file paths, crypto identifiers). |
| 08 | `08_command_table_dispatch` | Zig | 15 command handlers with sparse switch (gaps in opcodes), nested sub-command dispatch. |
| 09 | `09_prototype_reconstruction` | Zig | 21 functions with varied signatures (0-8 args), struct passing, stripped symbols. |
| 11 | `11_vtable_discovery` | C++ | 9 classes with vtables, inheritance hierarchy, virtual destructors, RTTI. |
| 12 | `12_decompiler_renaming` | Zig | 60+ functions calling well-known libc APIs (memcpy, strlen, socket, etc.), stripped. |
| 13 | `13_flattening_detection` | Zig | 6 manually flattened functions with dispatcher loops and state variables. |
| 16 | `16_auth_license_check_finder` | Zig | License key validation, serial checks, trial logic, HWID verification, feature unlocks. |
| 17 | `17_hook_surface_identification` | Zig | 28 exported functions across init/network/crypto/file boundaries, central dispatchers. |
| 18 | `18_binary_sarif_export` | Zig | Hardcoded secrets, dangerous APIs (strcpy, sprintf), anti-debug checks, high-entropy data. |
| 19 | `19_symbolic_constant_propagation` | Zig | 10 patterns with computed jumps, table lookups, XOR decryption with constant keys. |

### Skipped - Requires Alternative Approach (4 exercises)

| # | Exercise | Reason | Alternative in SKIP.md |
|---|----------|--------|------------------------|
| 10 | `10_function_chunk_repair` | LLVM doesn't produce cross-function shared tail blocks | Older GCC (4.x), hand-written assembly, real-world optimized binaries |
| 14 | `14_opaque_predicate_detection` | Compiler optimizes away trivial predicates in release builds | Tigress obfuscator, OLLVM, or use debug build (included) |
| 15 | `15_junk_block_cleanup` | LLVM eliminates dead code at all optimization levels | Tigress with junk insertion, raw x86-64 assembly, OLLVM |
| 20 | `20_scalable_project_annotator` | Impractical to generate 10k+ functions manually | Real binaries (FFmpeg, SQLite); includes download script |

## Building the Binaries

Each exercise folder contains:
- `prompt.txt` - Exercise description and requirements
- `src/` - Source code (Zig or C++)
- `Makefile` or `src/Makefile` - Build instructions

To build all exercises:

```bash
# Build each exercise
for dir in */src; do
    echo "Building $dir..."
    (cd "$dir" && make 2>/dev/null || make -C .. 2>/dev/null) || true
done
```

Or build individually:

```bash
cd 01_auto_tag_function_roles/src
make
```

### Build Requirements

- **Zig**: Version 0.11+ (most exercises)
- **Clang/GCC**: For C++ exercises (11_vtable_discovery)
- **strip**: For creating stripped binaries (usually included with toolchain)

### Cross-Compilation

Most Makefiles support cross-compilation targets:

```bash
make linux-x64      # x86_64 Linux ELF
make macos-x64      # x86_64 macOS Mach-O
make macos-arm64    # ARM64 macOS Mach-O
make windows-x64    # x86_64 Windows PE (where supported)
```

## Creating IDA Databases

After building, open each binary in IDA Pro to create the `.i64` database:

```bash
# Using IDA command line (example)
idat64 -A -o"input.i64" input
```

Or open interactively in IDA Pro and save the database.

## Exercise Structure

Each exercise prompt includes:

1. **Binary Requirements** - What the input binary should contain
2. **Task** - What the IDAPython script should accomplish
3. **Expected Output** - Format and content of results
4. **Expected Class of Solution** - Techniques and APIs to use
5. **Evaluation Criteria** - How to assess the solution

## Difficulty Progression

| Level | Exercises | Skills Required |
|-------|-----------|-----------------|
| **Beginner** | 01, 04, 07 | Basic IDA APIs, xrefs, string enumeration |
| **Intermediate** | 02, 03, 05, 08, 09, 12 | Callgraph traversal, pattern matching, type APIs |
| **Advanced** | 06, 11, 13, 16, 17, 18 | Struct creation, decompiler APIs, heuristic design |
| **Expert** | 10, 14, 15, 19, 20 | Microcode, symbolic execution, scalable architecture |

## Meta-Exercise

For senior candidates, consider this additional challenge:

> "Given this binary isn't quite what you expected, how would you adapt your script?"

This separates **tool users** from **tool builders** - the ability to:
- Diagnose when analysis fails
- Add new heuristics on the fly
- Balance automation vs. manual intervention
- Know when to cache vs. recompute

## License

These exercises are provided for educational and interview purposes.

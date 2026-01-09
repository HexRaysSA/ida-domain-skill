# Exercise 10: Zig Compilation Not Feasible

## Why Zig Cannot Produce This Binary

This exercise requires binaries with **shared tail blocks between functions** - basic blocks that are "owned" by multiple functions, causing IDA's auto-analysis to show warnings and function chunk issues.

Zig (using LLVM backend) **cannot reliably produce this pattern** because:

### 1. LLVM's Tail Merging is Intra-Function Only
LLVM's `-mllvm -enable-tail-merge` pass merges identical tail blocks *within* a single function, not across function boundaries. This is by design - functions are the unit of compilation.

### 2. Cross-Function Identical Code Folding (ICF) is a Linker Feature
ICF that merges identical functions is performed by linkers (ld.lld, gold with `--icf=all`), but:
- macOS's ld64 linker doesn't support aggressive ICF that creates shared blocks
- LLD doesn't support Mach-O linking
- Even with ICF, it typically merges entire functions, not tail blocks

### 3. Modern Compilers Avoid Shared Blocks
Modern compilers deliberately avoid creating shared basic blocks between functions because:
- It breaks assumptions in debuggers and profilers
- It complicates function boundary detection
- It's incompatible with many code analysis tools

## What Actually Creates Shared Tail Blocks

The patterns required for this exercise typically come from:

### Hand-Written Assembly
```nasm
func_a:
    ; ... function A body ...
    jmp shared_tail

func_b:
    ; ... function B body ...
    jmp shared_tail

shared_tail:
    ; Common cleanup code
    ret
```

### Old GCC Compilers (2.x/3.x)
Older GCC versions with `-freorder-blocks` and `-foptimize-sibling-calls` could create cross-function shared tails.

### Post-Link Optimizers
- **BOLT** (Binary Optimization and Layout Tool)
- **Propeller** (Google's profile-guided optimization)

### Obfuscated/Packed Binaries
Malware packers and obfuscators often create intentionally confusing function boundaries.

## Recommended Alternatives

### Option 1: Use C/C++ with Older GCC
```makefile
# Try GCC 4.x or earlier with aggressive optimization
gcc-4.9 -O3 -ffunction-sections -freorder-blocks -march=native src.c -o binary
```

### Option 2: Use Hand-Written Assembly
Create a NASM/MASM file that explicitly shares tail blocks:
```nasm
; shared_tails.asm
section .text
global process_a, process_b, process_c

process_a:
    mov rax, rdi
    imul rax, 3
    jmp common_epilogue

process_b:
    mov rax, rdi
    imul rax, 5
    jmp common_epilogue

process_c:
    mov rax, rdi
    imul rax, 7
    ; Falls through to common_epilogue

common_epilogue:
    ; Shared tail block - IDA will see this as part of multiple functions
    add rax, 100
    mov [rel global_result], rax
    ret
```

### Option 3: Use a Real-World Sample
Find an existing binary that exhibits this pattern:
- Windows system DLLs compiled with older MSVC
- Linux kernel modules (older versions)
- Malware samples from analysis repositories

### Option 4: Binary Patching
Create a normal binary and manually patch it to create shared tail blocks using a hex editor or binary patching tool.

## Compilation Command Used

```bash
# Attempted with Zig 0.15.2
zig build-lib -O ReleaseFast -dynamic main.zig -target x86_64-linux-gnu
```

Result: Functions are properly separated with no shared basic blocks.

## Verification

The generated binary was checked with:
```bash
objdump -d libmain.so | grep -E "\bjmp\s+" | sort | uniq -c | sort -rn
```

No cross-function jumps to shared blocks were found.

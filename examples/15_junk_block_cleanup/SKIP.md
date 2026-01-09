# Exercise 15: Junk Block Cleanup - Zig Not Feasible

## Why Zig Cannot Produce This Binary

The required junk/dead code patterns are fundamentally incompatible with how Zig (and its LLVM backend) work. Even at optimization level 0, modern compilers are designed to eliminate exactly the patterns this exercise requires:

### 1. Dead Code Elimination (DCE)
- **Dead stores**: Writes to never-read locations are automatically removed
- **Unreachable blocks**: Code after unconditional jumps is pruned during code generation
- **Unused computations**: Values computed but never used are eliminated

### 2. No-op Removal
Even without optimization, these patterns are removed during instruction selection:
- `add reg, 0` -> eliminated
- `xor reg, 0` -> eliminated
- `lea rax, [rax+0]` -> eliminated
- `xchg reg, reg` -> eliminated
- `mov rax, rbx; mov rbx, rax` -> eliminated as redundant

### 3. Register Shuffle Optimization
LLVM's register allocator and instruction combiner naturally eliminate register-to-register moves that have no net effect:
```
mov rax, rbx   ; These two cancel out
mov rbx, rax   ; LLVM will remove both
```

### 4. Inline Assembly Limitations
While Zig supports inline assembly via `asm volatile`, achieving the required patterns would require:
- Writing the entire function in raw assembly
- Carefully preventing LLVM from analyzing the assembly blocks
- Manual register allocation throughout

This defeats the purpose of using a high-level language.

---

## Recommended Alternatives

### Option 1: Tigress Obfuscator (Recommended)

[Tigress](https://tigress.wtf/) is a C source-to-source obfuscator with explicit junk insertion:

```bash
# Install Tigress, then:
tigress --Transform=AddOpaque --AddOpaqueKinds=junk \
        --Transform=CleanUp --CleanUpKinds=annotations \
        --out=junk_binary.c input.c
gcc -o junk_binary junk_binary.c
```

Tigress transformations for junk code:
- `AddOpaque` with `junk` kind: Inserts dead code blocks
- `Flatten`: Adds dispatcher-based obfuscation
- `EncodeArithmetic`: Adds complex no-op sequences

### Option 2: Raw x86-64 Assembly (NASM/GAS)

Write the binary directly in assembly to have complete control:

```nasm
; junk_patterns.asm
section .text
global junk_function

junk_function:
    ; Legitimate setup
    push rbp
    mov rbp, rsp

    ; JUNK: Register shuffle (net zero effect)
    mov rax, rbx
    mov rcx, rax
    mov rbx, rcx      ; rbx unchanged

    ; JUNK: Dead store
    mov [rsp-8], rax  ; Never read

    ; JUNK: No-op sequence
    xchg rax, rax
    lea rax, [rax+0]
    add rax, 0
    xor rax, 0

    ; JUNK: Always-true conditional
    xor ecx, ecx
    test ecx, ecx
    jnz .unreachable  ; Never taken

    ; Legitimate computation
    mov eax, edi
    add eax, esi

    ; JUNK: Unreachable block
    jmp .exit
.unreachable:
    mov rax, 0xDEADBEEF  ; Never executed
    ret

.exit:
    pop rbp
    ret
```

Build with:
```bash
nasm -f elf64 junk_patterns.asm -o junk_patterns.o
ld junk_patterns.o -o junk_binary
```

### Option 3: OLLVM (Obfuscator-LLVM)

Use the OLLVM fork of LLVM/Clang which has obfuscation passes:

```bash
# Build C code with OLLVM
clang-ollvm -mllvm -bcf -mllvm -boguscf -o junk_binary input.c
```

The `-boguscf` (Bogus Control Flow) pass inserts junk blocks with opaque predicates.

### Option 4: Custom Post-Processing

1. Compile legitimate code with Zig
2. Use a binary rewriter (e.g., LIEF, Binary Ninja API) to insert junk instructions
3. Patch the binary to add unreachable blocks and dead stores

---

## Suggested Binary Specification

For maximum exercise value, the binary should include:

| Junk Type | Count | Example Pattern |
|-----------|-------|-----------------|
| Register shuffles | 8-10 | `mov rax,rbx; mov rbx,rax` |
| Dead stores | 6-8 | Store to stack slot never read |
| No-op sequences | 5-7 | `lea rax,[rax]; xchg rax,rax` |
| Unreachable blocks | 4-5 | Code after unconditional jump |
| Always-true branches | 3-4 | `xor ecx,ecx; test ecx,ecx; jnz .dead` |

**Total: 26-34 junk instances across 3-5 functions**

The junk should be interleaved with legitimate code to test the detector's precision and false-positive rate.

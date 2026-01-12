# Opaque Predicate Exercise - Compilation Notes

## Summary

The provided Zig source code (`src/opaque_predicates.zig`) contains 15 opaque predicate patterns, but **Zig's optimizer is very aggressive** and will eliminate most/all of them when compiled with optimization enabled.

## Compilation Results

### Debug Mode (Predicates Preserved)
```bash
cd src && zig build-exe opaque_predicates.zig -O Debug -femit-bin=opaque_debug
```
- All 15 opaque predicate functions are present as separate symbols
- Conditional branches and dead code paths are preserved
- Good for this reverse engineering exercise

### Release Mode (Predicates Optimized Away)
```bash
cd src && zig build-exe opaque_predicates.zig -O ReleaseSafe -femit-bin=opaque_release
```
- Most predicate functions are inlined and optimized
- Constant conditions are folded at compile time
- Dead code is eliminated
- **Not suitable for this exercise**

## Recommendation

Use the **Debug build** for this exercise. The opaque predicates are preserved and can be detected through pattern matching in IDA.

## Alternatives for Production-Quality Opaque Predicates

If you need opaque predicates that survive aggressive optimization, consider:

### 1. Tigress Obfuscator (Recommended)
- Website: http://tigress.cs.arizona.edu/
- Academic obfuscator with excellent opaque predicate insertion
- Supports various predicate types (arithmetic, aliasing, data structure based)
- Example:
  ```bash
  tigress --Transform=AddOpaque --Functions=main --OpaqueStructs=list \
          --OpaqueCount=10 --OpaquePredicate=true --out=obfuscated.c input.c
  ```

### 2. OLLVM (Obfuscator-LLVM)
- Fork of LLVM with obfuscation passes
- https://github.com/obfuscator-llvm/obfuscator
- Compile with: `clang -mllvm -bcf -mllvm -bcf_prob=100 input.c`

### 3. Manual Assembly Insertion
- Use inline assembly to insert predicates the compiler cannot analyze
- Example for GCC/Clang:
  ```c
  int x = get_input();
  int result;
  __asm__ volatile(
      "mov %1, %0\n"
      "xor %0, %0\n"     // x ^ x = 0
      "test %0, %0\n"
      "jnz dead_path\n"
      : "=r" (result)
      : "r" (x)
  );
  ```

### 4. Runtime-Dependent Predicates
- Use values from environment, time, or external sources
- Compiler cannot prove they are constant
- Example: `if (getenv("PATH") != NULL)` - always true in practice

### 5. Pointer/Aliasing-Based Predicates
- Use complex pointer arithmetic that defeats alias analysis
- `if (*p == *q)` where p and q secretly point to same location

## Opaque Predicates in the Zig Source

The source includes these patterns:

| # | Predicate | Type | Always |
|---|-----------|------|--------|
| 1 | x*x >= 0 (unsigned) | Arithmetic | True |
| 2 | x ^ x == 0 | XOR identity | True |
| 3 | (x \| 1) != 0 | OR with constant | True |
| 4 | x - x == 0 | Subtraction identity | True |
| 5 | (x & 0) == 0 | AND with zero | True |
| 6 | x * 0 == 0 | Multiplication by zero | True |
| 7 | (x \| x) == x | OR idempotent | True |
| 8 | x == x | Reflexive equality | True |
| 9 | 2*x == x+x | Distributive property | True |
| 10 | (x & x) == x | AND idempotent | True |
| 11 | x*(x+1) is even | Number theory | True |
| 12 | ~(x ^ ~x) == 0 | XOR complement | True |
| 13 | x != x | Reflexive inequality | False |
| 14 | (x ^ x) != 0 | XOR identity negated | False |
| 15 | (x + y) - y == x | Addition cancellation | True |

## Detection Strategy

When analyzing the debug binary in IDA:

1. Look for XOR of register with itself followed by conditional branch
2. Look for comparison of register with itself (CMP/TEST with same operand)
3. Look for AND/OR with 0 or -1 constants
4. Look for arithmetic that always produces the same result
5. Check if both branch targets exist but one is never executed

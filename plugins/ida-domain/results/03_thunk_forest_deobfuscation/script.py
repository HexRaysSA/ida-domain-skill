# Exercise 03: Deobfuscation Pass for Thunk Forests
# Identifies thunk functions, resolves chains to ultimate targets, and renames them
# Supports ARM64 patterns including tail-call optimized wrappers

from ida_domain.functions import FunctionFlags
from ida_domain.operands import ImmediateOperand, MemoryOperand

# Track visited functions to detect cycles
visited_in_chain = set()

def get_tail_jump_target(func):
    """
    Check if a function ends with an unconditional jump/branch to another function.
    This is the ARM64 tail-call pattern.
    Returns the target address if it's a tail-call thunk, None otherwise.
    """
    # Get all instructions in the function
    instructions = list(db.functions.get_instructions(func))

    if not instructions:
        return None

    # Find the last meaningful instruction
    last_insn = None
    for insn in reversed(instructions):
        mnem = db.instructions.get_mnemonic(insn)
        if mnem:
            last_insn = insn
            break

    if not last_insn:
        return None

    mnem = db.instructions.get_mnemonic(last_insn)
    mnem_lower = mnem.lower()

    # ARM64 patterns:
    # - B (unconditional branch) - tail call
    # - BR (branch register) - indirect tail call (usually PLT thunks)
    # x86/x64 patterns:
    # - jmp - tail call
    # - ret preceded by jmp (unusual but possible)

    if mnem_lower in ('b', 'jmp'):
        # Direct unconditional branch - get target from xrefs
        for xref in db.xrefs.from_ea(last_insn.ea):
            if xref.is_jump:
                # Make sure target is a valid function or address
                return xref.to_ea

        # Try to get target from operand directly
        operand = db.instructions.get_operand(last_insn, 0)
        if operand and isinstance(operand, ImmediateOperand) and operand.is_address():
            return operand.get_value()

    elif mnem_lower == 'br':
        # Indirect branch (ARM64) - try to resolve target from xrefs
        # IDA often knows the target from analysis
        for xref in db.xrefs.from_ea(last_insn.ea):
            if xref.is_jump:
                return xref.to_ea

    return None


def is_pure_plt_thunk(func):
    """
    Check if function is a pure PLT-style thunk (ADRL + BR or similar minimal pattern).
    """
    instructions = list(db.functions.get_instructions(func))

    # Filter out nops
    meaningful = []
    for insn in instructions:
        mnem = db.instructions.get_mnemonic(insn)
        if mnem and mnem.lower() not in ('nop', 'endbr64', 'endbr32'):
            meaningful.append(insn)

    # PLT thunks are typically 1-3 instructions
    if len(meaningful) <= 3:
        # Check if last instruction is a branch
        last_mnem = db.instructions.get_mnemonic(meaningful[-1])
        if last_mnem and last_mnem.lower() in ('b', 'br', 'jmp'):
            return True

    return False


def is_thunk_function(func):
    """
    Determine if a function is a thunk.
    A thunk is a function that:
    - Has FUNC_THUNK flag set by IDA, OR
    - Is a PLT-style thunk (minimal instructions ending in branch), OR
    - Ends with an unconditional branch to another function (tail-call)
    """
    # Check IDA's thunk flag first
    flags = db.functions.get_flags(func)
    if FunctionFlags.THUNK in flags:
        return True

    # Check for PLT-style thunk
    if is_pure_plt_thunk(func):
        return True

    # Check for tail-call pattern (ends with B/jmp to another function)
    target = get_tail_jump_target(func)
    if target:
        # Verify target is a different function
        target_func = db.functions.get_at(target)
        if target_func and target_func.start_ea != func.start_ea:
            return True

    return False


def resolve_thunk_chain(func_ea, chain=None, max_depth=20):
    """
    Follow thunk chain to ultimate destination.
    Returns (ultimate_target_ea, chain_list) or (None, chain_list) if unresolved.
    """
    if chain is None:
        chain = []

    # Cycle detection
    if func_ea in visited_in_chain:
        return (None, chain)  # Cycle detected

    # Depth limit
    if len(chain) >= max_depth:
        return (None, chain)

    visited_in_chain.add(func_ea)
    chain.append(func_ea)

    func = db.functions.get_at(func_ea)
    if not func:
        visited_in_chain.discard(func_ea)
        return (func_ea, chain)  # Not a function - external/imported

    target = get_tail_jump_target(func)

    if target is None:
        # Not a thunk - this is the ultimate destination
        visited_in_chain.discard(func_ea)
        return (func_ea, chain)

    # Recursively resolve
    result = resolve_thunk_chain(target, chain, max_depth)
    visited_in_chain.discard(func_ea)
    return result


def get_safe_name(ea):
    """Get a name at address, handling external/imported symbols."""
    func = db.functions.get_at(ea)
    if func:
        return db.functions.get_name(func)
    # Try to get name directly
    name = db.names.get_at(ea)
    return name if name else f"sub_{ea:X}"


def main():
    print("=" * 70)
    print("Exercise 03: Thunk Forest Deobfuscation")
    print("=" * 70)
    print()

    # Collect all thunk functions and their chains
    thunk_chains = []
    non_thunks = []

    print("Phase 1: Identifying thunk functions...")
    print("-" * 70)

    for func in db.functions:
        func_name = db.functions.get_name(func)

        if is_thunk_function(func):
            # Resolve the chain
            visited_in_chain.clear()
            ultimate_target, chain = resolve_thunk_chain(func.start_ea)

            if ultimate_target and len(chain) > 1:
                thunk_chains.append({
                    'func': func,
                    'name': func_name,
                    'chain': chain,
                    'ultimate_target': ultimate_target
                })
            elif ultimate_target:
                # Single-level thunk or self-reference
                non_thunks.append({'func': func, 'name': func_name})
        else:
            non_thunks.append({
                'func': func,
                'name': func_name
            })

    print(f"Found {len(thunk_chains)} thunk chains")
    print(f"Found {len(non_thunks)} non-thunk functions")
    print()

    # Report thunk chains
    print("Phase 2: Resolved Thunk Chains")
    print("-" * 70)

    # Group by ultimate target for cleaner output
    by_target = {}
    for tc in thunk_chains:
        target = tc['ultimate_target']
        if target not in by_target:
            by_target[target] = []
        by_target[target].append(tc)

    for target_ea, chains in sorted(by_target.items()):
        target_name = get_safe_name(target_ea)
        print(f"\nUltimate Target: {target_name} (0x{target_ea:08X})")
        print(f"  Chains leading to this target:")

        for tc in chains:
            chain_str = " -> ".join([f"{get_safe_name(ea)}" for ea in tc['chain']])
            depth = len(tc['chain']) - 1
            print(f"    [{depth} levels] {chain_str}")

    print()
    print("=" * 70)
    print("Phase 3: Thunk Renaming Recommendations")
    print("-" * 70)

    rename_count = 0
    for tc in thunk_chains:
        func = tc['func']
        current_name = tc['name']
        ultimate_target = tc['ultimate_target']
        target_name = get_safe_name(ultimate_target)

        # Skip if function is the ultimate target itself
        if func.start_ea == ultimate_target:
            continue

        # Generate new name
        # Remove leading underscore if present for cleaner naming
        clean_target = target_name.lstrip('_')
        depth = len(tc['chain']) - 1

        if depth == 1:
            new_name = f"thunk_{clean_target}"
        else:
            new_name = f"thunk{depth}_{clean_target}"

        # Only print if name would change significantly
        if current_name != new_name:
            print(f"  0x{func.start_ea:08X}: {current_name} -> {new_name}")
            rename_count += 1

    if rename_count == 0:
        print("  (No renaming recommendations)")

    print()
    print("=" * 70)
    print("Phase 4: Summary Statistics")
    print("-" * 70)

    # Calculate statistics
    depths = {}
    for tc in thunk_chains:
        depth = len(tc['chain']) - 1
        depths[depth] = depths.get(depth, 0) + 1

    print(f"Total functions analyzed: {len(thunk_chains) + len(non_thunks)}")
    print(f"Thunk functions found: {len(thunk_chains)}")
    print(f"Ultimate targets: {len(by_target)}")
    print()
    print("Chain depth distribution:")
    for depth in sorted(depths.keys()):
        count = depths[depth]
        print(f"  {depth} level(s): {count} thunk(s)")

    print()
    print("=" * 70)
    print("Phase 5: Detailed Chain Report (Top 20 deepest chains)")
    print("-" * 70)

    # Sort by chain depth and show top 20
    sorted_chains = sorted(thunk_chains, key=lambda x: -len(x['chain']))[:20]

    for i, tc in enumerate(sorted_chains):
        chain = tc['chain']
        depth = len(chain) - 1

        print(f"\nChain #{i+1} (depth={depth}):")
        for j, ea in enumerate(chain):
            name = get_safe_name(ea)
            if j == 0:
                print(f"  START: {name} (0x{ea:08X})")
            elif j == len(chain) - 1:
                print(f"  {'  ' * j}-> ULTIMATE: {name} (0x{ea:08X})")
            else:
                print(f"  {'  ' * j}-> {name} (0x{ea:08X})")

    print()
    print("=" * 70)
    print("Analysis complete!")
    print("=" * 70)


# Run the analysis
main()

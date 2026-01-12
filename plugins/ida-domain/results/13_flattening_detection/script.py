# Control Flow Flattening Detector
# Detects control-flow flattening patterns and generates annotations

from collections import defaultdict
import json

# Flattening detection thresholds
MIN_BLOCKS_FOR_FLATTENING = 5  # Minimum blocks to consider flattening
MIN_SWITCH_CASES = 3  # Minimum switch cases to consider
HIGH_PREDECESSOR_THRESHOLD = 3  # A dispatcher typically has many predecessors

def analyze_function_for_flattening(func):
    """
    Analyze a function for control-flow flattening patterns.

    Returns a dict with detection results or None if not flattened.
    """
    func_name = db.functions.get_name(func)
    flowchart = db.functions.get_flowchart(func)

    if not flowchart or len(flowchart) < MIN_BLOCKS_FOR_FLATTENING:
        return None

    blocks = list(flowchart)
    block_count = len(blocks)

    # Build predecessor/successor maps
    pred_count = {}
    succ_count = {}
    block_map = {}  # start_ea -> block

    for block in blocks:
        pred_count[block.start_ea] = block.count_predecessors()
        succ_count[block.start_ea] = block.count_successors()
        block_map[block.start_ea] = block

    # Look for dispatcher pattern:
    # 1. A block with many predecessors (return point from case blocks)
    # 2. That block has successors (switch dispatch)
    # 3. High ratio of blocks returning to the same point

    dispatcher_candidates = []

    for block in blocks:
        preds = pred_count[block.start_ea]
        succs = succ_count[block.start_ea]

        # Dispatcher typically has: many predecessors OR is the entry + many successors
        # Or it's part of a loop where many blocks jump back to it
        if preds >= HIGH_PREDECESSOR_THRESHOLD and succs >= 2:
            dispatcher_candidates.append({
                'block': block,
                'predecessors': preds,
                'successors': succs,
                'score': preds * succs  # Higher score = more likely dispatcher
            })

    # Also check for indirect jump patterns (switch-like behavior)
    # by looking at blocks that have high out-degree
    for block in blocks:
        succs = succ_count[block.start_ea]
        if succs >= MIN_SWITCH_CASES:
            # Check if this isn't already a candidate
            if not any(c['block'].start_ea == block.start_ea for c in dispatcher_candidates):
                dispatcher_candidates.append({
                    'block': block,
                    'predecessors': pred_count[block.start_ea],
                    'successors': succs,
                    'score': succs * 2  # Weight successors for switch detection
                })

    if not dispatcher_candidates:
        return None

    # Sort by score and pick the best candidate
    dispatcher_candidates.sort(key=lambda x: x['score'], reverse=True)
    best_candidate = dispatcher_candidates[0]

    # Verify flattening pattern:
    # In flattened code, most blocks should either:
    # 1. Jump to the dispatcher
    # 2. Be a successor of the dispatcher
    dispatcher_ea = best_candidate['block'].start_ea
    dispatcher_block = best_candidate['block']

    # Count blocks that connect to dispatcher
    blocks_to_dispatcher = 0
    blocks_from_dispatcher = 0

    for block in blocks:
        # Check successors
        for succ in block.get_successors():
            if succ.start_ea == dispatcher_ea:
                blocks_to_dispatcher += 1
                break

        # Check predecessors
        for pred in block.get_predecessors():
            if pred.start_ea == dispatcher_ea:
                blocks_from_dispatcher += 1
                break

    # Calculate flattening score
    # A highly flattened function has most blocks connected to dispatcher
    connection_ratio = (blocks_to_dispatcher + blocks_from_dispatcher) / (block_count * 2)

    # Heuristic: if more than 30% of blocks connect to one block, likely flattened
    # Also check cyclomatic complexity indicator
    total_edges = sum(succ_count.values())
    cyclomatic = total_edges - block_count + 2

    # Flattening tends to create high cyclomatic complexity relative to block count
    is_flattened = (
        connection_ratio > 0.25 or
        (best_candidate['successors'] >= MIN_SWITCH_CASES and
         best_candidate['predecessors'] >= MIN_SWITCH_CASES - 1)
    )

    if not is_flattened:
        return None

    # Identify state variable by analyzing the dispatcher block
    state_var_info = analyze_state_variable(func, dispatcher_block)

    # Map case blocks (successors of dispatcher)
    case_blocks = []
    for i, succ in enumerate(dispatcher_block.get_successors()):
        case_blocks.append({
            'index': i,
            'start_ea': succ.start_ea,
            'end_ea': succ.end_ea,
            'successors': succ.count_successors(),
            'predecessors': succ.count_predecessors()
        })

    return {
        'function_name': func_name,
        'function_start': func.start_ea,
        'function_end': func.end_ea,
        'block_count': block_count,
        'cyclomatic_complexity': cyclomatic,
        'dispatcher': {
            'start_ea': dispatcher_ea,
            'end_ea': dispatcher_block.end_ea,
            'predecessors': best_candidate['predecessors'],
            'successors': best_candidate['successors'],
            'score': best_candidate['score']
        },
        'connection_ratio': connection_ratio,
        'case_blocks': case_blocks,
        'state_variable': state_var_info,
        'blocks_to_dispatcher': blocks_to_dispatcher,
        'blocks_from_dispatcher': blocks_from_dispatcher
    }


def analyze_state_variable(func, dispatcher_block):
    """
    Attempt to identify the state variable used in the dispatcher.

    Analyzes instructions in the dispatcher block looking for:
    - Comparisons (cmp, test)
    - Switch-like patterns (indirect jumps based on register)
    """
    state_info = {
        'identified': False,
        'location': None,
        'type': 'unknown'
    }

    try:
        # Get instructions in the dispatcher block
        instructions = list(dispatcher_block.get_instructions())

        for insn in instructions:
            mnem = db.instructions.get_mnemonic(insn)
            if not mnem:
                continue

            mnem_lower = mnem.lower()

            # Look for comparison instructions
            if mnem_lower in ['cmp', 'test']:
                operands = db.instructions.get_operands(insn)
                if operands:
                    state_info['identified'] = True
                    state_info['type'] = 'comparison'
                    state_info['location'] = f"0x{insn.ea:08X}"
                    state_info['instruction'] = db.instructions.get_disassembly(insn)
                    break

            # Look for indirect jumps (switch pattern)
            if mnem_lower in ['jmp', 'switch']:
                if db.instructions.is_indirect_jump_or_call(insn):
                    state_info['identified'] = True
                    state_info['type'] = 'indirect_jump'
                    state_info['location'] = f"0x{insn.ea:08X}"
                    state_info['instruction'] = db.instructions.get_disassembly(insn)
                    break
    except Exception as e:
        state_info['error'] = str(e)

    return state_info


def annotate_flattened_function(result):
    """
    Add comments and annotations to help with analysis.
    Note: This creates the annotation strings but actual database modification
    requires --save flag.
    """
    annotations = []

    # Dispatcher annotation
    dispatcher_ea = result['dispatcher']['start_ea']
    dispatcher_comment = (
        f"[FLATTENING DISPATCHER]\n"
        f"Predecessors: {result['dispatcher']['predecessors']}\n"
        f"Successors: {result['dispatcher']['successors']}\n"
        f"Detection Score: {result['dispatcher']['score']}"
    )
    annotations.append({
        'ea': dispatcher_ea,
        'type': 'dispatcher',
        'comment': dispatcher_comment
    })

    # Case block annotations
    for case in result['case_blocks']:
        case_comment = (
            f"[CASE BLOCK {case['index']}]\n"
            f"Range: 0x{case['start_ea']:08X} - 0x{case['end_ea']:08X}"
        )
        annotations.append({
            'ea': case['start_ea'],
            'type': 'case_block',
            'index': case['index'],
            'comment': case_comment
        })

    return annotations


def generate_graphviz(result):
    """
    Generate Graphviz DOT representation of the flattened CFG.
    """
    lines = []
    lines.append(f'digraph "{result["function_name"]}" {{')
    lines.append('    rankdir=TB;')
    lines.append('    node [shape=box, style=filled];')
    lines.append('')

    # Dispatcher node (highlighted)
    dispatcher_ea = result['dispatcher']['start_ea']
    lines.append(f'    block_{dispatcher_ea:08X} [label="DISPATCHER\\n0x{dispatcher_ea:08X}", fillcolor=yellow];')

    # Case block nodes
    for case in result['case_blocks']:
        lines.append(f'    block_{case["start_ea"]:08X} [label="Case {case["index"]}\\n0x{case["start_ea"]:08X}", fillcolor=lightblue];')

    # Edges from dispatcher to cases
    for case in result['case_blocks']:
        lines.append(f'    block_{dispatcher_ea:08X} -> block_{case["start_ea"]:08X};')

    # Edges from cases back to dispatcher (implied by flattening)
    for case in result['case_blocks']:
        lines.append(f'    block_{case["start_ea"]:08X} -> block_{dispatcher_ea:08X} [style=dashed, color=gray];')

    lines.append('}')
    return '\n'.join(lines)


def main():
    """Main analysis routine."""
    print("=" * 70)
    print("CONTROL-FLOW FLATTENING DETECTOR")
    print("=" * 70)
    print(f"Binary: {db.module}")
    print(f"Architecture: {db.architecture} {db.bitness}-bit")
    print(f"Total functions: {len(db.functions)}")
    print("=" * 70)
    print()

    flattened_functions = []

    # Analyze all functions
    for func in db.functions:
        result = analyze_function_for_flattening(func)
        if result:
            flattened_functions.append(result)

    # Report findings
    print(f"DETECTION RESULTS")
    print("-" * 70)
    print(f"Flattened functions detected: {len(flattened_functions)}")
    print()

    if not flattened_functions:
        print("No control-flow flattening patterns detected.")
        print()
        print("This could mean:")
        print("  - The binary is not obfuscated with CFF")
        print("  - The obfuscation uses a different pattern")
        print("  - Detection thresholds may need adjustment")
        return

    # Detailed report for each flattened function
    for i, result in enumerate(flattened_functions, 1):
        print(f"\n{'=' * 70}")
        print(f"FLATTENED FUNCTION {i}: {result['function_name']}")
        print(f"{'=' * 70}")
        print()

        print("FUNCTION INFO:")
        print(f"  Address Range: 0x{result['function_start']:08X} - 0x{result['function_end']:08X}")
        print(f"  Basic Blocks: {result['block_count']}")
        print(f"  Cyclomatic Complexity: {result['cyclomatic_complexity']}")
        print()

        print("DISPATCHER IDENTIFICATION:")
        print(f"  Location: 0x{result['dispatcher']['start_ea']:08X} - 0x{result['dispatcher']['end_ea']:08X}")
        print(f"  Predecessor Count: {result['dispatcher']['predecessors']}")
        print(f"  Successor Count: {result['dispatcher']['successors']}")
        print(f"  Detection Score: {result['dispatcher']['score']}")
        print(f"  Connection Ratio: {result['connection_ratio']:.2%}")
        print()

        print("STATE VARIABLE:")
        sv = result['state_variable']
        if sv['identified']:
            print(f"  Type: {sv['type']}")
            print(f"  Location: {sv['location']}")
            if 'instruction' in sv:
                print(f"  Instruction: {sv['instruction']}")
        else:
            print("  Could not identify state variable")
            if 'error' in sv:
                print(f"  Error: {sv['error']}")
        print()

        print("STATE-TO-BLOCK MAPPING (Case Blocks):")
        print(f"  {'Index':<8} {'Start Address':<18} {'End Address':<18} {'Succs':<8} {'Preds':<8}")
        print(f"  {'-' * 60}")
        for case in result['case_blocks']:
            print(f"  {case['index']:<8} 0x{case['start_ea']:08X}{'':8} 0x{case['end_ea']:08X}{'':8} {case['successors']:<8} {case['predecessors']:<8}")
        print()

        print("FLOW STATISTICS:")
        print(f"  Blocks jumping TO dispatcher: {result['blocks_to_dispatcher']}")
        print(f"  Blocks jumping FROM dispatcher: {result['blocks_from_dispatcher']}")
        print()

        # Generate annotations
        annotations = annotate_flattened_function(result)
        print("SUGGESTED ANNOTATIONS:")
        for ann in annotations:
            print(f"  @ 0x{ann['ea']:08X} [{ann['type']}]")
            for line in ann['comment'].split('\n'):
                print(f"    {line}")
        print()

        # Generate Graphviz
        dot = generate_graphviz(result)
        print("GRAPHVIZ CFG (copy to .dot file):")
        print("-" * 40)
        print(dot)
        print("-" * 40)

    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total flattened functions: {len(flattened_functions)}")
    print()
    print("Function List:")
    for result in flattened_functions:
        print(f"  - {result['function_name']} @ 0x{result['function_start']:08X}")
        print(f"    Blocks: {result['block_count']}, Dispatcher successors: {result['dispatcher']['successors']}")

    # Export JSON summary
    print()
    print("=" * 70)
    print("JSON EXPORT (for further processing):")
    print("=" * 70)
    export_data = []
    for result in flattened_functions:
        export_data.append({
            'function': result['function_name'],
            'start_ea': f"0x{result['function_start']:08X}",
            'block_count': result['block_count'],
            'dispatcher_ea': f"0x{result['dispatcher']['start_ea']:08X}",
            'case_count': len(result['case_blocks']),
            'connection_ratio': result['connection_ratio']
        })
    print(json.dumps(export_data, indent=2))


# Run the analysis
main()

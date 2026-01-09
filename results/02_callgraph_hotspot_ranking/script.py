# Callgraph Hotspot Ranking
# Builds a callgraph from entrypoints, computes graph metrics, and ranks
# the top "central" functions most likely to be dispatchers or protocol handlers.

from collections import defaultdict
from pathlib import Path

# Configuration
TOP_N = 20  # Number of top hotspots to display

# Build the callgraph
print("=" * 70)
print("CALLGRAPH HOTSPOT RANKING")
print("=" * 70)

# Get binary info
print(f"\nBinary: {db.module}")
print(f"Architecture: {db.architecture} {db.bitness}-bit")

# Build adjacency lists for the callgraph
# callers[func_ea] = set of functions that call func
# callees[func_ea] = set of functions that func calls
callers = defaultdict(set)
callees = defaultdict(set)
all_functions = {}

print("\nBuilding callgraph...")
func_count = 0
for func in db.functions:
    func_ea = func.start_ea
    func_name = db.functions.get_name(func)
    all_functions[func_ea] = func_name
    func_count += 1

    # Get all functions called by this function
    for callee in db.functions.get_callees(func):
        callee_ea = callee.start_ea
        callees[func_ea].add(callee_ea)
        callers[callee_ea].add(func_ea)

print(f"Total functions: {func_count}")
print(f"Functions with callers: {len(callers)}")
print(f"Functions with callees: {len(callees)}")

# Calculate metrics for each function
# fan_in: number of unique callers
# fan_out: number of unique callees
# combined: fan_in + fan_out (connectivity)
# product: fan_in * fan_out (hub score - functions that both receive and make many calls)

metrics = {}
for func_ea, func_name in all_functions.items():
    fan_in = len(callers.get(func_ea, set()))
    fan_out = len(callees.get(func_ea, set()))
    combined = fan_in + fan_out
    product = fan_in * fan_out

    metrics[func_ea] = {
        'name': func_name,
        'fan_in': fan_in,
        'fan_out': fan_out,
        'combined': combined,
        'product': product,
    }

# Get entrypoints
print("\n" + "=" * 70)
print("ENTRYPOINTS")
print("=" * 70)
entrypoints = []
for entry in db.entries:
    entrypoints.append(entry.address)
    func = db.functions.get_at(entry.address)
    func_name = db.functions.get_name(func) if func else entry.name
    print(f"  0x{entry.address:08X}: {func_name}")

if not entrypoints:
    print("  (No entrypoints found)")

# Calculate depth from entrypoints using BFS
print("\nCalculating depth from entrypoints...")
depth = {}
if entrypoints:
    visited = set()
    queue = [(ea, 0) for ea in entrypoints if ea in all_functions]

    while queue:
        func_ea, d = queue.pop(0)
        if func_ea in visited:
            continue
        visited.add(func_ea)
        depth[func_ea] = d

        # Add callees at depth+1
        for callee_ea in callees.get(func_ea, set()):
            if callee_ea not in visited:
                queue.append((callee_ea, d + 1))

    print(f"Functions reachable from entrypoints: {len(depth)}")
else:
    print("Skipping depth calculation (no entrypoints)")

# Add depth to metrics
for func_ea in all_functions:
    metrics[func_ea]['depth'] = depth.get(func_ea, -1)  # -1 means unreachable

# Betweenness approximation: count how many paths pass through each function
# Using a simplified approach: for each entrypoint, do BFS and count visits
print("Computing betweenness approximation...")
betweenness = defaultdict(int)

if entrypoints:
    for entry_ea in entrypoints:
        if entry_ea not in all_functions:
            continue

        # BFS from this entrypoint
        visited = set()
        queue = [entry_ea]

        while queue:
            func_ea = queue.pop(0)
            if func_ea in visited:
                continue
            visited.add(func_ea)
            betweenness[func_ea] += 1

            for callee_ea in callees.get(func_ea, set()):
                if callee_ea not in visited:
                    queue.append(callee_ea)

for func_ea in all_functions:
    metrics[func_ea]['betweenness'] = betweenness.get(func_ea, 0)

# Detect strongly connected components (Tarjan's algorithm)
print("Detecting strongly connected components...")

index_counter = [0]
stack = []
lowlink = {}
index = {}
on_stack = {}
sccs = []

def strongconnect(v):
    index[v] = index_counter[0]
    lowlink[v] = index_counter[0]
    index_counter[0] += 1
    stack.append(v)
    on_stack[v] = True

    for w in callees.get(v, set()):
        if w not in all_functions:
            continue
        if w not in index:
            strongconnect(w)
            lowlink[v] = min(lowlink[v], lowlink[w])
        elif on_stack.get(w, False):
            lowlink[v] = min(lowlink[v], index[w])

    if lowlink[v] == index[v]:
        scc = []
        while True:
            w = stack.pop()
            on_stack[w] = False
            scc.append(w)
            if w == v:
                break
        if len(scc) > 1:  # Only keep non-trivial SCCs
            sccs.append(scc)

# Use iteration limit to avoid stack overflow on large graphs
import sys
old_limit = sys.getrecursionlimit()
sys.setrecursionlimit(10000)

try:
    for v in all_functions:
        if v not in index:
            try:
                strongconnect(v)
            except RecursionError:
                print(f"  Warning: Recursion limit reached for function at 0x{v:08X}")
                continue
finally:
    sys.setrecursionlimit(old_limit)

# Mark functions in SCCs
scc_membership = {}
for i, scc in enumerate(sccs):
    for func_ea in scc:
        scc_membership[func_ea] = i

for func_ea in all_functions:
    metrics[func_ea]['in_scc'] = func_ea in scc_membership
    metrics[func_ea]['scc_id'] = scc_membership.get(func_ea, -1)

# Compute composite hotspot score
# Weight factors for ranking:
# - High fan-in indicates frequently called code
# - High fan-out indicates dispatcher/router functions
# - High product indicates hub functions
# - Low depth from entrypoint indicates early processing
# - Being in SCC indicates mutual recursion / callback pattern

for func_ea, m in metrics.items():
    # Normalize and combine
    fan_in_score = m['fan_in'] * 2  # Weight callers higher
    fan_out_score = m['fan_out'] * 1.5
    product_score = m['product'] * 0.5
    betweenness_score = m['betweenness'] * 1.0

    # Depth bonus: functions closer to entrypoint score higher
    if m['depth'] >= 0:
        depth_score = max(0, 10 - m['depth']) * 2  # Max 20 points for depth 0
    else:
        depth_score = 0

    # SCC bonus for mutual recursion patterns
    scc_score = 10 if m['in_scc'] else 0

    m['hotspot_score'] = (fan_in_score + fan_out_score + product_score +
                          betweenness_score + depth_score + scc_score)

# Rank by hotspot score
ranked = sorted(metrics.items(), key=lambda x: x[1]['hotspot_score'], reverse=True)

# Output results
print("\n" + "=" * 70)
print(f"TOP {TOP_N} HOTSPOT FUNCTIONS (Potential Dispatchers/Handlers)")
print("=" * 70)
print(f"{'Rank':<5} {'Address':<12} {'Name':<35} {'Score':<8} {'In':<4} {'Out':<4} {'Depth':<6} {'SCC'}")
print("-" * 90)

for i, (func_ea, m) in enumerate(ranked[:TOP_N], 1):
    name = m['name'][:34] if len(m['name']) > 34 else m['name']
    depth_str = str(m['depth']) if m['depth'] >= 0 else "N/A"
    scc_str = f"#{m['scc_id']}" if m['in_scc'] else "-"
    print(f"{i:<5} 0x{func_ea:08X}  {name:<35} {m['hotspot_score']:<8.1f} {m['fan_in']:<4} {m['fan_out']:<4} {depth_str:<6} {scc_str}")

# Detailed metrics for top 5
print("\n" + "=" * 70)
print("DETAILED METRICS FOR TOP 5 HOTSPOTS")
print("=" * 70)

for i, (func_ea, m) in enumerate(ranked[:5], 1):
    print(f"\n{i}. {m['name']} (0x{func_ea:08X})")
    print(f"   Fan-in (callers):     {m['fan_in']}")
    print(f"   Fan-out (callees):    {m['fan_out']}")
    print(f"   Combined connectivity: {m['combined']}")
    print(f"   Hub score (in*out):   {m['product']}")
    print(f"   Betweenness:          {m['betweenness']}")
    print(f"   Depth from entry:     {m['depth'] if m['depth'] >= 0 else 'Unreachable'}")
    print(f"   In SCC:               {'Yes (mutual recursion)' if m['in_scc'] else 'No'}")
    print(f"   HOTSPOT SCORE:        {m['hotspot_score']:.1f}")

# SCC Report
if sccs:
    print("\n" + "=" * 70)
    print("STRONGLY CONNECTED COMPONENTS (Mutual Recursion / Dispatch Loops)")
    print("=" * 70)

    for i, scc in enumerate(sccs):
        print(f"\nSCC #{i} ({len(scc)} functions):")
        for func_ea in scc[:10]:  # Limit display for large SCCs
            name = all_functions.get(func_ea, f"sub_{func_ea:X}")
            print(f"  0x{func_ea:08X}: {name}")
        if len(scc) > 10:
            print(f"  ... and {len(scc) - 10} more functions")
else:
    print("\n" + "=" * 70)
    print("No non-trivial strongly connected components found.")
    print("=" * 70)

# Graph statistics summary
print("\n" + "=" * 70)
print("CALLGRAPH STATISTICS")
print("=" * 70)
total_edges = sum(len(c) for c in callees.values())
avg_fan_out = total_edges / func_count if func_count > 0 else 0
avg_fan_in = total_edges / func_count if func_count > 0 else 0
max_fan_in = max((m['fan_in'] for m in metrics.values()), default=0)
max_fan_out = max((m['fan_out'] for m in metrics.values()), default=0)

print(f"Total functions:          {func_count}")
print(f"Total call edges:         {total_edges}")
print(f"Average fan-out:          {avg_fan_out:.2f}")
print(f"Max fan-in:               {max_fan_in}")
print(f"Max fan-out:              {max_fan_out}")
print(f"SCCs (mutual recursion):  {len(sccs)}")
if entrypoints:
    reachable = len([m for m in metrics.values() if m['depth'] >= 0])
    print(f"Reachable from entry:     {reachable} ({100*reachable/func_count:.1f}%)")

# Export graphviz DOT file with hotspots highlighted
print("\n" + "=" * 70)
print("GRAPHVIZ EXPORT")
print("=" * 70)

dot_path = Path("/tmp/callgraph_hotspots.dot")
hotspot_eas = set(ea for ea, _ in ranked[:TOP_N])
entry_set = set(entrypoints)

with open(dot_path, 'w') as f:
    f.write("digraph callgraph {\n")
    f.write("  rankdir=TB;\n")
    f.write("  node [shape=box, fontname=\"Courier\", fontsize=10];\n")
    f.write("  edge [color=gray60];\n\n")

    # Define node styles
    f.write("  // Entrypoints (green)\n")
    for ea in entry_set:
        if ea in all_functions:
            name = all_functions[ea].replace('"', '\\"')
            f.write(f'  "0x{ea:08X}" [label="{name}", style=filled, fillcolor=lightgreen];\n')

    f.write("\n  // Hotspots (red/orange gradient by rank)\n")
    for i, (ea, m) in enumerate(ranked[:TOP_N]):
        if ea not in entry_set:
            name = m['name'].replace('"', '\\"')
            if i < 5:
                color = "red"
            elif i < 10:
                color = "orange"
            else:
                color = "yellow"
            f.write(f'  "0x{ea:08X}" [label="{name}\\n[#{i+1}]", style=filled, fillcolor={color}];\n')

    f.write("\n  // Edges (limited to hotspots for readability)\n")
    for ea in hotspot_eas | entry_set:
        for callee_ea in callees.get(ea, set()):
            if callee_ea in hotspot_eas or callee_ea in entry_set:
                f.write(f'  "0x{ea:08X}" -> "0x{callee_ea:08X}";\n')

    f.write("}\n")

print(f"DOT file written to: {dot_path}")
print("To render: dot -Tpng /tmp/callgraph_hotspots.dot -o /tmp/callgraph_hotspots.png")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)

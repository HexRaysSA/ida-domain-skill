# Hook Surface Identification for Dynamic Instrumentation
# Identifies good hook points for Frida/DynamoRIO in a stripped binary
# Works by analyzing function structure, call patterns, and data flow

import json
from collections import defaultdict

# Categories for hook candidates
HOOK_CATEGORIES = {
    'EXPORT': 'Exported functions - stable, easy to hook by name',
    'ENTRY_POINT': 'Entry points - program start, good for early hooks',
    'HIGH_FANOUT': 'High fan-out - calls many functions, likely dispatcher/coordinator',
    'HIGH_FANIN': 'High fan-in - called by many, central utility/wrapper',
    'STRING_RICH': 'String-rich - references many strings, likely logging/error handling',
    'LARGE_FUNCTION': 'Large function - complex logic, potential high-value target',
    'BOUNDARY': 'Boundary function - interface between subsystems',
    'WRAPPER': 'Thin wrapper - wraps single callee, good for API interception',
}

def guess_calling_convention(func, db):
    """Guess the calling convention based on architecture and function signature."""
    arch = db.architecture
    bitness = db.bitness

    if arch and 'ARM' in arch.upper():
        return 'ARM AAPCS' if bitness == 32 else 'ARM64 AAPCS64'
    elif arch and 'metapc' in arch.lower():
        return 'cdecl' if bitness == 32 else 'System V AMD64 ABI'
    else:
        return 'Unknown (platform-specific)'

def analyze_string_references(func, db):
    """Count strings referenced by a function."""
    string_refs = []
    try:
        # Get xrefs from the function range
        for ea in range(func.start_ea, func.end_ea):
            for xref in db.xrefs.from_ea(ea):
                # Check if target is in strings
                for s in db.strings:
                    if s.address == xref.to_ea:
                        try:
                            content = str(s)[:50]
                            string_refs.append((xref.to_ea, content))
                        except:
                            pass
                        break
    except:
        pass
    return string_refs

def calculate_hook_priority(func, callers_count, callees_count, func_size, is_export, string_count, categories):
    """Calculate priority score for a hook candidate."""
    score = 0

    # Exports are most valuable (stable hooks)
    if is_export:
        score += 50

    # High fan-in (many callers) - central functions
    if callers_count >= 5:
        score += 25
    elif callers_count >= 3:
        score += 15
    elif callers_count >= 1:
        score += 5

    # High fan-out (many callees) - dispatchers/coordinators
    if callees_count >= 10:
        score += 30
    elif callees_count >= 5:
        score += 20
    elif callees_count >= 3:
        score += 10

    # Function size indicates complexity
    if func_size >= 5000:
        score += 15  # Very large - complex logic
    elif func_size >= 1000:
        score += 10
    elif func_size >= 500:
        score += 5

    # String references - logging/error handling
    if string_count >= 5:
        score += 15
    elif string_count >= 2:
        score += 10

    # Wrapper functions (few callees, many callers) - good API boundaries
    if callees_count == 1 and callers_count >= 2:
        score += 20

    # Category bonuses
    if 'ENTRY_POINT' in categories:
        score += 30
    if 'HIGH_FANOUT' in categories:
        score += 20
    if 'WRAPPER' in categories:
        score += 15

    return score

def categorize_by_structure(func, callers_count, callees_count, func_size, string_count, is_export):
    """Categorize function based on its structural properties."""
    categories = []

    if is_export:
        categories.append('EXPORT')

    if callers_count == 0 and callees_count > 0:
        categories.append('ENTRY_POINT')

    if callees_count >= 10:
        categories.append('HIGH_FANOUT')

    if callers_count >= 5:
        categories.append('HIGH_FANIN')

    if string_count >= 3:
        categories.append('STRING_RICH')

    if func_size >= 2000:
        categories.append('LARGE_FUNCTION')

    if callees_count == 1 and callers_count >= 2:
        categories.append('WRAPPER')

    # Boundary detection: calls other functions but also called by others
    if callers_count >= 2 and callees_count >= 2 and callees_count <= 5:
        categories.append('BOUNDARY')

    return categories

def get_suggested_instrumentation(categories, callees_count, string_count):
    """Generate instrumentation suggestions based on function characteristics."""
    suggestions = []

    if 'ENTRY_POINT' in categories:
        suggestions.append("Hook early - capture initialization flow")
        suggestions.append("Log startup parameters")

    if 'HIGH_FANOUT' in categories:
        suggestions.append("Central dispatcher - log dispatch targets")
        suggestions.append("Filter/redirect specific operations")

    if 'HIGH_FANIN' in categories:
        suggestions.append("Widely used utility - log all calls")
        suggestions.append("Monitor data flow through this point")

    if 'STRING_RICH' in categories:
        suggestions.append("Logging/error handling - capture messages")
        suggestions.append("Identify error conditions")

    if 'WRAPPER' in categories:
        suggestions.append("API wrapper - intercept underlying call")
        suggestions.append("Modify arguments/return values")

    if 'BOUNDARY' in categories:
        suggestions.append("Subsystem boundary - trace data between modules")

    if 'LARGE_FUNCTION' in categories:
        suggestions.append("Complex logic - multiple hook points within")

    if not suggestions:
        suggestions.append("Log entry/exit and arguments")

    return suggestions

# Main analysis
print("=" * 80)
print("HOOK SURFACE IDENTIFICATION REPORT")
print("Binary Analysis for Dynamic Instrumentation (Frida/DynamoRIO)")
print("=" * 80)
print()

# Get basic binary info
print(f"Module: {db.module}")
print(f"Architecture: {db.architecture}")
print(f"Bitness: {db.bitness}-bit")
print(f"Base Address: 0x{db.base_address:08X}" if db.base_address else "Base Address: Unknown")
print()

# Collect exports
print("-" * 80)
print("PHASE 1: Collecting Entry Points and Exports")
print("-" * 80)

exports = {}
for entry in db.entries:
    exports[entry.address] = entry.name
    print(f"  Entry/Export: {entry.name} @ 0x{entry.address:08X}")

print(f"\nTotal entries/exports: {len(exports)}")
print()

# Build call graph and analyze functions
print("-" * 80)
print("PHASE 2: Building Call Graph and Analyzing Functions")
print("-" * 80)

func_data = {}
all_strings = list(db.strings)
string_addrs = {s.address for s in all_strings}

total_funcs = len(db.functions)
print(f"Analyzing {total_funcs} functions...")

for func in db.functions:
    name = db.functions.get_name(func)
    if not name:
        name = f"sub_{func.start_ea:X}"

    ea = func.start_ea
    func_size = func.end_ea - func.start_ea

    # Get callers and callees
    callers = db.functions.get_callers(func)
    callees = db.functions.get_callees(func)

    # Count string references (simplified - check data xrefs)
    string_refs = []
    try:
        for inst_ea in range(func.start_ea, min(func.start_ea + 500, func.end_ea)):
            for xref in db.xrefs.from_ea(inst_ea):
                if xref.to_ea in string_addrs:
                    string_refs.append(xref.to_ea)
    except:
        pass

    func_data[ea] = {
        'name': name,
        'ea': ea,
        'size': func_size,
        'callers': [c.start_ea for c in callers],
        'callees': [c.start_ea for c in callees],
        'callers_count': len(callers),
        'callees_count': len(callees),
        'string_refs': list(set(string_refs)),
        'is_export': ea in exports,
    }

print(f"Analysis complete.")
print()

# Categorize and score functions
print("-" * 80)
print("PHASE 3: Categorizing Hook Candidates")
print("-" * 80)

hook_candidates = []

for ea, data in func_data.items():
    categories = categorize_by_structure(
        None,  # func object not needed for this
        data['callers_count'],
        data['callees_count'],
        data['size'],
        len(data['string_refs']),
        data['is_export']
    )

    # Skip functions with no interesting characteristics
    if not categories:
        continue

    priority = calculate_hook_priority(
        None,
        data['callers_count'],
        data['callees_count'],
        data['size'],
        data['is_export'],
        len(data['string_refs']),
        categories
    )

    suggestions = get_suggested_instrumentation(
        categories,
        data['callees_count'],
        len(data['string_refs'])
    )

    calling_conv = 'System V AMD64 ABI'  # Default for x64

    # Determine why it's a good hook point
    reasons = []
    if data['is_export']:
        reasons.append("Export/Entry point - stable hook by name")
    if 'HIGH_FANOUT' in categories:
        reasons.append(f"High fan-out ({data['callees_count']} callees) - dispatcher candidate")
    if 'HIGH_FANIN' in categories:
        reasons.append(f"High fan-in ({data['callers_count']} callers) - central utility")
    if 'WRAPPER' in categories:
        reasons.append("Thin wrapper - single callee with multiple callers")
    if 'STRING_RICH' in categories:
        reasons.append(f"References {len(data['string_refs'])} strings - logging/messages")
    if 'LARGE_FUNCTION' in categories:
        reasons.append(f"Large function ({data['size']} bytes) - complex logic")
    if 'ENTRY_POINT' in categories:
        reasons.append("Entry point - no callers, good for early hooks")
    if 'BOUNDARY' in categories:
        reasons.append("Boundary function - interface between subsystems")

    hook_candidates.append({
        'name': data['name'],
        'ea': ea,
        'categories': categories,
        'is_export': data['is_export'],
        'calling_conv': calling_conv,
        'callers_count': data['callers_count'],
        'callees_count': data['callees_count'],
        'size': data['size'],
        'string_count': len(data['string_refs']),
        'priority': priority,
        'reasons': reasons,
        'suggestions': suggestions,
    })

# Sort by priority (highest first)
hook_candidates.sort(key=lambda x: x['priority'], reverse=True)

print(f"Found {len(hook_candidates)} hook candidates")
print()

# Output by category
print("-" * 80)
print("PHASE 4: Hook Candidates by Category")
print("-" * 80)

for cat, desc in HOOK_CATEGORIES.items():
    cat_funcs = [h for h in hook_candidates if cat in h['categories']]
    if not cat_funcs:
        continue

    print(f"\n### {cat}: {desc}")
    print()

    for hc in sorted(cat_funcs, key=lambda x: x['priority'], reverse=True)[:10]:
        print(f"  Function: {hc['name']}")
        print(f"    EA: 0x{hc['ea']:08X}")
        print(f"    Size: {hc['size']} bytes")
        print(f"    Callers: {hc['callers_count']}, Callees: {hc['callees_count']}")
        print(f"    Priority Score: {hc['priority']}")
        print(f"    Why hook: {'; '.join(hc['reasons'][:3])}")
        print(f"    Suggested: {'; '.join(hc['suggestions'][:2])}")
        print()

# Priority ranking
print("-" * 80)
print("PHASE 5: Priority Ranking (Top 25 Hook Points)")
print("-" * 80)
print()
print(f"{'Rank':<6}{'Priority':<10}{'Function':<24}{'Size':<10}{'In/Out':<12}{'Categories'}")
print("-" * 80)

for i, hc in enumerate(hook_candidates[:25], 1):
    cats = ', '.join(hc['categories'][:2])
    fanio = f"{hc['callers_count']}/{hc['callees_count']}"
    print(f"{i:<6}{hc['priority']:<10}{hc['name']:<24}{hc['size']:<10}{fanio:<12}{cats}")

print()

# Generate Frida snippet examples
print("-" * 80)
print("PHASE 6: Frida Snippet Templates")
print("-" * 80)
print()

# Example for entry point
if hook_candidates:
    top = hook_candidates[0]
    print(f"// Hook for {top['name']} (Priority: {top['priority']})")
    print(f"// Categories: {', '.join(top['categories'])}")
    print(f"""
var base = Module.findBaseAddress("{db.module}");
var funcAddr = base.add(0x{top['ea'] - db.base_address:X});

Interceptor.attach(funcAddr, {{
    onEnter: function(args) {{
        console.log("[{top['name']}] Called from: " + this.returnAddress);
        console.log("  arg0: " + args[0]);
        console.log("  arg1: " + args[1]);
        console.log("  arg2: " + args[2]);
    }},
    onLeave: function(retval) {{
        console.log("[{top['name']}] Returned: " + retval);
    }}
}});
""")

# High fan-out dispatcher example
high_fanout = [h for h in hook_candidates if 'HIGH_FANOUT' in h['categories']]
if high_fanout:
    disp = high_fanout[0]
    print(f"// Hook for dispatcher {disp['name']} (calls {disp['callees_count']} functions)")
    print(f"""
var base = Module.findBaseAddress("{db.module}");
var dispatchAddr = base.add(0x{disp['ea'] - db.base_address:X});

Interceptor.attach(dispatchAddr, {{
    onEnter: function(args) {{
        console.log("[DISPATCH] {disp['name']}");
        console.log("  Possible command/opcode: " + args[0]);
        console.log("  Possible arg1: " + args[1]);
        console.log("  Possible arg2: " + args[2]);
    }},
    onLeave: function(retval) {{
        console.log("[DISPATCH] Result: " + retval);
    }}
}});
""")

# Wrapper function example
wrappers = [h for h in hook_candidates if 'WRAPPER' in h['categories']]
if wrappers:
    wrap = wrappers[0]
    print(f"// Hook for wrapper {wrap['name']} (thin wrapper with {wrap['callers_count']} callers)")
    print(f"""
var base = Module.findBaseAddress("{db.module}");
var wrapperAddr = base.add(0x{wrap['ea'] - db.base_address:X});

Interceptor.attach(wrapperAddr, {{
    onEnter: function(args) {{
        console.log("[WRAPPER] {wrap['name']} - intercept at API boundary");
        // Dump buffer if it looks like data
        if (args[1].toInt32() > 0 && args[1].toInt32() < 0x10000) {{
            try {{
                console.log("  Data: " + hexdump(args[0], {{ length: Math.min(args[1].toInt32(), 64) }}));
            }} catch(e) {{}}
        }}
    }},
    onLeave: function(retval) {{
        console.log("[WRAPPER] Result: " + retval);
    }}
}});
""")

# Summary statistics
print("-" * 80)
print("SUMMARY")
print("-" * 80)
print()
print(f"Binary: {db.module}")
print(f"Architecture: {db.architecture} {db.bitness}-bit")
print(f"Base Address: 0x{db.base_address:08X}")
print(f"Total functions analyzed: {len(func_data)}")
print(f"Total hook candidates: {len(hook_candidates)}")
print()

cat_counts = defaultdict(int)
for hc in hook_candidates:
    for cat in hc['categories']:
        cat_counts[cat] += 1

print("Candidates by category:")
for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {cat}: {count}")

print()
print("Top 10 highest priority hooks:")
for i, hc in enumerate(hook_candidates[:10], 1):
    offset = hc['ea'] - db.base_address if db.base_address else hc['ea']
    print(f"  {i}. {hc['name']} (base+0x{offset:X}) - Priority: {hc['priority']}")

print()
print("-" * 80)
print("HOOK SURFACE ANALYSIS RECOMMENDATIONS")
print("-" * 80)
print()
print("For dynamic instrumentation of this binary:")
print()
print("1. PRIMARY TARGETS (High Priority):")
for hc in hook_candidates[:5]:
    offset = hc['ea'] - db.base_address if db.base_address else hc['ea']
    print(f"   - {hc['name']} @ base+0x{offset:X}")
    print(f"     Categories: {', '.join(hc['categories'])}")
    print(f"     Reason: {hc['reasons'][0] if hc['reasons'] else 'N/A'}")
    print()

if high_fanout:
    print("2. DISPATCHER FUNCTIONS (Command/Message Routing):")
    for hc in high_fanout[:3]:
        offset = hc['ea'] - db.base_address if db.base_address else hc['ea']
        print(f"   - {hc['name']} @ base+0x{offset:X} (calls {hc['callees_count']} functions)")

print()
if wrappers:
    print("3. WRAPPER/BOUNDARY FUNCTIONS (API Interception):")
    for hc in wrappers[:5]:
        offset = hc['ea'] - db.base_address if db.base_address else hc['ea']
        print(f"   - {hc['name']} @ base+0x{offset:X} ({hc['callers_count']} callers)")

print()
print("=" * 80)
print("Analysis complete. Hook surface report generated.")
print("=" * 80)

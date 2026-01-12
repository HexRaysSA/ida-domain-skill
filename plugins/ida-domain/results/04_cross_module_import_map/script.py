"""
Exercise 04: Cross-Module Import Usage Map

Enumerate imports and build a per-import usage map:
- Which functions call which imports
- Call frequency per import
- Call site addresses

Bonus: Detect dynamically resolved imports (GetProcAddress patterns)
"""

import json
from collections import defaultdict

# Build import usage map
import_usage = {}  # import_name -> {address, callers: [{func_name, call_site, count}]}
per_function_profile = {}  # func_name -> {imports: [...], total_import_calls}
pseudo_imports = []  # Dynamically resolved imports

# Find the extern/import segment(s)
extern_segments = []
for seg in db.segments:
    seg_class = db.segments.get_class(seg)
    seg_name = db.segments.get_name(seg)
    if seg_class == "XTRN" or seg_name in ["extern", ".plt", ".got.plt", "UNDEF", ".idata"]:
        extern_segments.append(seg)
        print(f"Found extern segment: {seg_name} (0x{seg.start_ea:08X} - 0x{seg.end_ea:08X})")

# Enumerate all names in extern segments as imports
import_addresses = {}  # address -> import_name
for seg in extern_segments:
    # Iterate through all addresses in the segment
    ea = seg.start_ea
    while ea < seg.end_ea:
        name = db.names.get_at(ea)
        if name:
            import_addresses[ea] = name
            import_usage[name] = {
                "address": f"0x{ea:08X}",
                "callers": [],
                "total_calls": 0
            }
        ea += 8 if db.bitness == 64 else 4

# Also check for imports via entries/exports that are forwarders
for entry in db.entries:
    if entry.has_forwarder():
        name = entry.name
        if name not in import_usage:
            import_addresses[entry.address] = name
            import_usage[name] = {
                "address": f"0x{entry.address:08X}",
                "callers": [],
                "total_calls": 0,
                "forwarder": entry.forwarder_name
            }

# If no extern segments found, try to identify imports by name patterns
if not import_addresses:
    print("No extern segments found, scanning all names for import patterns...")
    for ea, name in db.names:
        # Common import naming patterns
        if name.startswith("_imp_") or name.startswith("__imp_") or \
           name.startswith("j_") or "@@" in name:  # versioned symbols like printf@@GLIBC
            import_addresses[ea] = name
            import_usage[name] = {
                "address": f"0x{ea:08X}",
                "callers": [],
                "total_calls": 0
            }

print(f"\nFound {len(import_addresses)} imports")

# Build caller map for each import
caller_counts = defaultdict(lambda: defaultdict(int))  # import_name -> func_name -> count
call_sites = defaultdict(list)  # import_name -> [(func_name, call_site_ea)]

for import_ea, import_name in import_addresses.items():
    try:
        # Get all call references to this import
        for xref in db.xrefs.to_ea(import_ea):
            call_site = xref.from_ea

            # Find the function containing this call site
            func = db.functions.get_at(call_site)
            if func:
                func_name = db.functions.get_name(func)
            else:
                func_name = f"unknown_0x{call_site:08X}"

            caller_counts[import_name][func_name] += 1
            call_sites[import_name].append((func_name, call_site))

            # Update per-function profile
            if func_name not in per_function_profile:
                per_function_profile[func_name] = {
                    "address": f"0x{func.start_ea:08X}" if func else "unknown",
                    "imports": defaultdict(int),
                    "total_import_calls": 0
                }
            per_function_profile[func_name]["imports"][import_name] += 1
            per_function_profile[func_name]["total_import_calls"] += 1
    except Exception as e:
        # Skip invalid addresses
        continue

# Consolidate caller information into import_usage
for import_name in import_usage:
    callers_list = []
    for func_name, count in caller_counts[import_name].items():
        # Get unique call sites for this function
        sites = [f"0x{site:08X}" for fn, site in call_sites[import_name] if fn == func_name]
        callers_list.append({
            "caller_func": func_name,
            "count": count,
            "call_sites": sites
        })
    import_usage[import_name]["callers"] = callers_list
    import_usage[import_name]["total_calls"] = sum(c["count"] for c in callers_list)

# Convert per_function_profile imports from defaultdict to regular dict
for func_name in per_function_profile:
    per_function_profile[func_name]["imports"] = dict(per_function_profile[func_name]["imports"])

# BONUS: Detect dynamically resolved imports (GetProcAddress/dlsym patterns)
dynamic_resolver_funcs = ["GetProcAddress", "dlsym", "_GetProcAddress@8", "_dlsym"]
resolver_addresses = {}

# Find addresses of GetProcAddress/dlsym
for import_ea, import_name in import_addresses.items():
    base_name = import_name.lstrip("_").split("@")[0]  # Handle decorated names
    if base_name in ["GetProcAddress", "dlsym"]:
        resolver_addresses[import_ea] = import_name
        print(f"Found dynamic resolver: {import_name} at 0x{import_ea:08X}")

# Also search by name directly
for base_resolver in dynamic_resolver_funcs:
    func = db.functions.get_function_by_name(base_resolver)
    if func:
        resolver_addresses[func.start_ea] = base_resolver
        print(f"Found dynamic resolver function: {base_resolver} at 0x{func.start_ea:08X}")

# Analyze calls to GetProcAddress/dlsym to find pseudo-imports
for resolver_ea, resolver_name in resolver_addresses.items():
    try:
        for xref in db.xrefs.to_ea(resolver_ea):
            call_site = xref.from_ea
            func = db.functions.get_at(call_site)
            if func:
                caller_name = db.functions.get_name(func)
            else:
                caller_name = f"unknown_0x{call_site:08X}"

            # Try to find the string argument (function name being resolved)
            # Look for string references near the call site
            resolved_name = None
            try:
                # Search backwards from call site for string references
                search_start = call_site - 32 if call_site > 32 else 0
                for ea in range(search_start, call_site + 8):
                    try:
                        for data_xref in db.xrefs.from_ea(ea):
                            if data_xref.to_ea:
                                # Check if this is a string
                                for s in db.strings:
                                    if s.address == data_xref.to_ea:
                                        resolved_name = str(s)
                                        break
                                if resolved_name:
                                    break
                    except:
                        continue
                    if resolved_name:
                        break
            except:
                pass

            pseudo_imports.append({
                "resolver": resolver_name,
                "call_site": f"0x{call_site:08X}",
                "caller_func": caller_name,
                "resolved_name": resolved_name if resolved_name else "unknown"
            })
    except:
        continue

# Build the final output
output = {
    "summary": {
        "total_imports": len(import_addresses),
        "imports_with_references": len([i for i in import_usage.values() if i["total_calls"] > 0]),
        "total_call_sites": sum(i["total_calls"] for i in import_usage.values()),
        "functions_using_imports": len(per_function_profile),
        "pseudo_imports_detected": len(pseudo_imports)
    },
    "import_usage_map": import_usage,
    "per_function_import_profile": per_function_profile,
    "pseudo_imports": pseudo_imports
}

# Print summary
print("\n" + "=" * 60)
print("CROSS-MODULE IMPORT USAGE MAP")
print("=" * 60)
print(f"\nSummary:")
print(f"  Total imports found: {output['summary']['total_imports']}")
print(f"  Imports with references: {output['summary']['imports_with_references']}")
print(f"  Total call sites: {output['summary']['total_call_sites']}")
print(f"  Functions using imports: {output['summary']['functions_using_imports']}")
print(f"  Pseudo-imports detected: {output['summary']['pseudo_imports_detected']}")

# Top 10 most called imports
print("\nTop 10 Most Called Imports:")
sorted_imports = sorted(import_usage.items(), key=lambda x: x[1]["total_calls"], reverse=True)[:10]
for i, (name, data) in enumerate(sorted_imports, 1):
    print(f"  {i}. {name}: {data['total_calls']} calls from {len(data['callers'])} functions")

# Top 10 functions with most import calls
print("\nTop 10 Functions by Import Usage:")
sorted_funcs = sorted(per_function_profile.items(),
                      key=lambda x: x[1]["total_import_calls"], reverse=True)[:10]
for i, (name, data) in enumerate(sorted_funcs, 1):
    unique_imports = len(data["imports"])
    print(f"  {i}. {name}: {data['total_import_calls']} import calls ({unique_imports} unique imports)")

# Pseudo-imports (dynamically resolved)
if pseudo_imports:
    print("\nDynamically Resolved Pseudo-Imports:")
    for pi in pseudo_imports[:20]:  # Show first 20
        print(f"  {pi['resolver']} called at {pi['call_site']} by {pi['caller_func']}")
        if pi['resolved_name'] != "unknown":
            print(f"    -> Resolves: {pi['resolved_name']}")

# Output JSON
print("\n" + "=" * 60)
print("JSON OUTPUT:")
print("=" * 60)
print(json.dumps(output, indent=2))

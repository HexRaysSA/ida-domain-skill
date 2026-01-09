# Exercise 16: Find and Verify Auth/License Checks
# Analyze binary to locate license/auth enforcement points using strings, imports, and control flow

import re
from collections import defaultdict

# License-related string patterns to search for
LICENSE_PATTERNS = [
    # License/key related
    r'licen[cs]e',
    r'serial',
    r'trial',
    r'expir',
    r'valid',
    r'invalid',
    r'unlock',
    r'feature',
    r'auth',
    r'password',
    r'check',
    r'verify',
    r'key',
    r'activ',
    r'hwid',
    r'hardware',
    r'register',
    r'subscription',
    r'renew',
    r'purchase',
]

# Crypto/security related API patterns
CRYPTO_PATTERNS = [
    r'crypt',
    r'hash',
    r'signature',
    r'rsa',
    r'aes',
    r'md5',
    r'sha',
    r'hmac',
]

# Error/success message patterns
MESSAGE_PATTERNS = [
    r'success',
    r'fail',
    r'denied',
    r'granted',
    r'access',
    r'welcome',
    r'error',
    r'mismatch',
]

print("=" * 80)
print("AUTH/LICENSE CHECK FINDER - ANALYSIS REPORT")
print("=" * 80)
print()

# Step 1: Find all license-related strings
print("=" * 80)
print("STEP 1: IDENTIFYING LICENSE-RELATED STRINGS")
print("=" * 80)
print()

license_strings = []  # (address, string_content, matched_patterns)
all_patterns = LICENSE_PATTERNS + CRYPTO_PATTERNS + MESSAGE_PATTERNS

for s in db.strings:
    try:
        content = str(s)
        content_lower = content.lower()

        matched = []
        for pattern in all_patterns:
            if re.search(pattern, content_lower):
                matched.append(pattern)

        if matched:
            license_strings.append((s.address, content, matched))
    except:
        continue

# Sort by address
license_strings.sort(key=lambda x: x[0])

print(f"Found {len(license_strings)} license-related strings:")
print()
for addr, content, patterns in license_strings:
    # Truncate long strings
    display = content[:60] + "..." if len(content) > 60 else content
    display = display.replace('\n', '\\n').replace('\r', '\\r')
    print(f"  0x{addr:08X}: \"{display}\"")
    print(f"             Matched: {', '.join(patterns[:3])}")
print()

# Step 2: Find functions that reference license strings
print("=" * 80)
print("STEP 2: IDENTIFYING CANDIDATE CHECK FUNCTIONS")
print("=" * 80)
print()

# Map string addresses to functions that reference them
string_to_functions = defaultdict(list)
function_evidence = defaultdict(lambda: {"strings": [], "string_refs": 0, "decision_points": [], "callers": []})

for addr, content, patterns in license_strings:
    # Find xrefs to this string
    for xref in db.xrefs.to_ea(addr):
        from_ea = xref.from_ea
        # Find which function this xref is in
        for func in db.functions:
            if func.start_ea <= from_ea < func.end_ea:
                func_name = db.functions.get_name(func)
                string_to_functions[addr].append((func, func_name, from_ea))
                function_evidence[func.start_ea]["strings"].append((addr, content[:40], patterns))
                function_evidence[func.start_ea]["string_refs"] += 1
                function_evidence[func.start_ea]["func"] = func
                function_evidence[func.start_ea]["name"] = func_name
                break

# Find candidate functions (those with multiple license-related string references)
candidate_functions = []
for func_ea, evidence in function_evidence.items():
    if evidence["string_refs"] >= 1:  # At least 1 license-related string
        candidate_functions.append((func_ea, evidence))

# Sort by number of string references (most suspicious first)
candidate_functions.sort(key=lambda x: x[1]["string_refs"], reverse=True)

print(f"Found {len(candidate_functions)} candidate check functions:")
print()

for func_ea, evidence in candidate_functions[:30]:  # Top 30
    func_name = evidence["name"]
    print(f"  Function: {func_name}")
    print(f"  Address:  0x{func_ea:08X}")
    print(f"  License String References: {evidence['string_refs']}")
    print(f"  Strings:")
    for str_addr, str_content, patterns in evidence["strings"][:5]:
        display = str_content.replace('\n', '\\n')[:35]
        print(f"    - 0x{str_addr:08X}: \"{display}...\" [{patterns[0]}]")
    print()

# Step 3: Analyze control flow for decision points
print("=" * 80)
print("STEP 3: ANALYZING DECISION POINTS IN CHECK FUNCTIONS")
print("=" * 80)
print()

def analyze_function_branches(func):
    """Analyze function for decision branches (success vs failure paths)"""
    decisions = []

    try:
        flowchart = db.functions.get_flowchart(func)
        if not flowchart:
            return decisions

        for block in flowchart:
            # Count successors - blocks with 2+ successors are decision points
            successors = list(block.succs())
            if len(successors) >= 2:
                decisions.append({
                    "block_start": block.start_ea,
                    "block_end": block.end_ea,
                    "num_branches": len(successors),
                    "branch_targets": [s.start_ea for s in successors]
                })
    except:
        pass

    return decisions

# Analyze top candidate functions
print("Detailed Analysis of Top Candidate Functions:")
print()

detailed_candidates = []
for func_ea, evidence in candidate_functions[:15]:  # Analyze top 15
    func = evidence["func"]
    func_name = evidence["name"]

    # Get decision points
    decisions = analyze_function_branches(func)

    # Get callers (where this check is invoked)
    callers = []
    try:
        caller_funcs = db.functions.get_callers(func)
        for caller in caller_funcs:
            caller_name = db.functions.get_name(caller)
            callers.append((caller.start_ea, caller_name))
    except:
        pass

    # Try to get pseudocode for deeper analysis
    pseudocode = None
    try:
        lines = db.functions.get_pseudocode(func)
        pseudocode = "\n".join(lines)
    except:
        pass

    detailed_candidates.append({
        "func_ea": func_ea,
        "name": func_name,
        "evidence": evidence,
        "decisions": decisions,
        "callers": callers,
        "pseudocode": pseudocode,
        "size": func.end_ea - func.start_ea
    })

for cand in detailed_candidates:
    print("-" * 60)
    print(f"FUNCTION: {cand['name']}")
    print(f"Address:  0x{cand['func_ea']:08X}")
    print(f"Size:     {cand['size']} bytes")
    print()

    print("Evidence (License-related strings):")
    for str_addr, str_content, patterns in cand["evidence"]["strings"]:
        display = str_content.replace('\n', '\\n')[:50]
        print(f"  - \"{display}\"")
    print()

    print(f"Decision Points: {len(cand['decisions'])}")
    for i, dec in enumerate(cand["decisions"][:5]):
        print(f"  [{i+1}] Block 0x{dec['block_start']:08X} - 0x{dec['block_end']:08X}")
        print(f"      Branches to: {', '.join(f'0x{t:08X}' for t in dec['branch_targets'][:3])}")
    print()

    print(f"Call Sites ({len(cand['callers'])} callers):")
    for caller_ea, caller_name in cand["callers"][:5]:
        print(f"  - {caller_name} at 0x{caller_ea:08X}")
    print()

# Step 4: Generate patch strategy suggestions
print("=" * 80)
print("STEP 4: SUGGESTED PATCH STRATEGIES")
print("=" * 80)
print()
print("NOTE: For analysis purposes only - DO NOT actually patch")
print()

for cand in detailed_candidates:
    func_name = cand["name"]
    func_ea = cand["func_ea"]

    # Determine suggested patch strategy based on function characteristics
    strategies = []

    # Check for boolean return patterns
    has_bool_return = False
    has_error_string = False
    has_success_string = False

    for str_addr, str_content, patterns in cand["evidence"]["strings"]:
        content_lower = str_content.lower()
        if any(p in content_lower for p in ["fail", "invalid", "error", "denied", "expired", "mismatch"]):
            has_error_string = True
        if any(p in content_lower for p in ["success", "valid", "unlock", "welcome", "granted"]):
            has_success_string = True

    if has_error_string and has_success_string:
        strategies.append("FORCE_SUCCESS: Patch to always return success/true (mov eax, 1; ret)")

    if cand["decisions"]:
        strategies.append("NOP_CHECK: NOP the conditional jump at decision point to skip validation")
        strategies.append("INVERT_BRANCH: Invert conditional jump (JZ <-> JNZ) to swap success/failure paths")

    if not strategies:
        strategies.append("HOOK_RETURN: Hook function entry to always return desired value")

    print(f"Function: {func_name} (0x{func_ea:08X})")
    print("Suggested Strategies:")
    for strat in strategies:
        print(f"  - {strat}")

    if cand["decisions"]:
        print(f"Primary Patch Point: 0x{cand['decisions'][0]['block_end']:08X} (decision block end)")
    print()

# Step 5: Summary report
print("=" * 80)
print("STEP 5: SUMMARY REPORT")
print("=" * 80)
print()

# Categorize functions by type
exported_checks = []
internal_checks = []
helper_functions = []

for cand in detailed_candidates:
    name = cand["name"]
    # Heuristic: exported functions or those with many callers are main check points
    if len(cand["callers"]) == 0 or name.startswith("check_") or name.startswith("validate") or name.startswith("verify") or name.startswith("full_") or name.startswith("authenticate") or name.startswith("online_") or name.startswith("is_") or name.startswith("get_"):
        exported_checks.append(cand)
    elif len(cand["callers"]) > 2:
        helper_functions.append(cand)
    else:
        internal_checks.append(cand)

print("EXPORTED/MAIN CHECK FUNCTIONS:")
for cand in exported_checks:
    print(f"  - {cand['name']} at 0x{cand['func_ea']:08X}")
    print(f"    Decision points: {len(cand['decisions'])}, Callers: {len(cand['callers'])}")
print()

print("INTERNAL CHECK FUNCTIONS:")
for cand in internal_checks:
    print(f"  - {cand['name']} at 0x{cand['func_ea']:08X}")
    print(f"    Decision points: {len(cand['decisions'])}, Callers: {len(cand['callers'])}")
print()

print("HELPER/UTILITY FUNCTIONS:")
for cand in helper_functions:
    print(f"  - {cand['name']} at 0x{cand['func_ea']:08X}")
    print(f"    Decision points: {len(cand['decisions'])}, Callers: {len(cand['callers'])}")
print()

print("=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
print()
print(f"Total license-related strings found: {len(license_strings)}")
print(f"Total candidate check functions: {len(candidate_functions)}")
print(f"Functions analyzed in detail: {len(detailed_candidates)}")
print()
print("Key findings:")
print("  - Identified multiple license validation patterns")
print("  - Located decision points for success/failure branches")
print("  - Mapped call sites where checks are invoked")
print("  - Provided patch strategy suggestions (for analysis only)")

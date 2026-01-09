# Exercise 07: Build a String Provenance Report
# For every interesting string (matched by regex: URL, IP, path, registry, etc.):
# 1. Find all xrefs to the string
# 2. Trace up the caller chain (configurable depth)
# 3. Compute the set of functions that produce or consume it
# 4. Group strings by "feature" category

import re
import json
from collections import defaultdict

# Configuration
MAX_CALLER_DEPTH = 3  # How far up the call chain to trace

# Define regex patterns for interesting strings by category
PATTERNS = {
    "Network": [
        (r"https?://[^\s\"'<>]+", "URL"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP Address"),
        (r"\b(?:tcp|udp)://[^\s\"']+", "Protocol URL"),
        (r":\d{2,5}\b", "Port"),
        (r"/api/[^\s\"']+", "API Endpoint"),
        (r"\.(?:com|net|org|io|gov|edu)\b", "Domain"),
    ],
    "Persistence": [
        (r"HKEY_[A-Z_]+\\[^\s\"']+", "Registry Key"),
        (r"\\Software\\[^\s\"']+", "Registry Software Key"),
        (r"\\CurrentVersion\\Run", "Autorun Registry"),
        (r"/etc/init\.d/", "Linux Init"),
        (r"\.service\b", "Systemd Service"),
        (r"crontab|/etc/cron", "Cron Job"),
        (r"\\Startup\\", "Windows Startup"),
    ],
    "Anti-Debug": [
        (r"IsDebuggerPresent", "Debug API"),
        (r"NtQueryInformationProcess", "Debug API"),
        (r"CheckRemoteDebuggerPresent", "Debug API"),
        (r"OutputDebugString", "Debug API"),
        (r"ptrace", "Debug API"),
        (r"HWID|VMware|VirtualBox|QEMU|Hyper-V", "VM Detection"),
        (r"Sandbox|SbieDll", "Sandbox Detection"),
    ],
    "File_Operations": [
        (r"[A-Za-z]:\\[^\s\"']+", "Windows Path"),
        (r"/(?:home|root|tmp|var|usr|etc)/[^\s\"']+", "Unix Path"),
        (r"\.(?:exe|dll|sys|bat|cmd|ps1|sh|py|js)\b", "Executable Extension"),
        (r"\.(?:txt|log|cfg|ini|conf|json|xml|yaml)\b", "Config Extension"),
        (r"\.(?:dat|db|sqlite)\b", "Data Extension"),
        (r"CreateFile|ReadFile|WriteFile|DeleteFile", "File API"),
        (r"fopen|fread|fwrite|fclose", "C File API"),
    ],
    "Crypto": [
        (r"\b(?:AES|DES|RSA|SHA|MD5|HMAC|RC4|Blowfish)\b", "Algorithm"),
        (r"(?:public|private)_?key", "Key Reference"),
        (r"encrypt|decrypt|cipher", "Crypto Operation"),
        (r"base64|b64|hex", "Encoding"),
        (r"certificate|\.pem|\.crt|\.key", "Certificate"),
        (r"random|rand|seed", "Random"),
    ],
}

def classify_string(s):
    """Classify a string into categories based on regex patterns."""
    categories = []
    try:
        content = str(s)
    except:
        return categories

    for category, patterns in PATTERNS.items():
        for pattern, subtype in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE):
                    categories.append((category, subtype, pattern))
            except:
                continue

    return categories

def get_function_name_at(ea):
    """Get the function name containing an address."""
    func = db.functions.get_at(ea)
    if func:
        return db.functions.get_name(func)
    return None

def get_caller_chain(start_ea, depth=MAX_CALLER_DEPTH):
    """Trace the caller chain up to a given depth."""
    chains = []
    visited = set()

    def trace(ea, current_chain, current_depth):
        if current_depth >= depth:
            if current_chain:
                chains.append(list(current_chain))
            return

        func = db.functions.get_at(ea)
        if not func:
            if current_chain:
                chains.append(list(current_chain))
            return

        func_name = db.functions.get_name(func)
        func_ea = func.start_ea

        if func_ea in visited:
            if current_chain:
                chains.append(list(current_chain))
            return

        visited.add(func_ea)
        current_chain.append((func_ea, func_name))

        # Get callers of this function
        callers = db.functions.get_callers(func)
        if not callers:
            chains.append(list(current_chain))
        else:
            for caller in callers:
                trace(caller.start_ea, current_chain, current_depth + 1)

        current_chain.pop()
        visited.discard(func_ea)

    trace(start_ea, [], 0)
    return chains

def analyze_strings():
    """Main analysis function."""
    # Group results by category
    report = defaultdict(list)

    print("=" * 80)
    print("STRING PROVENANCE REPORT")
    print("=" * 80)
    print()

    # Analyze all strings
    string_count = 0
    interesting_count = 0

    for s in db.strings:
        string_count += 1

        try:
            content = str(s)
        except:
            continue

        # Classify the string
        categories = classify_string(s)
        if not categories:
            continue

        interesting_count += 1
        string_ea = s.address

        # Find all xrefs to this string
        xrefs_info = []
        try:
            for xref in db.xrefs.to_ea(string_ea):
                func_name = get_function_name_at(xref.from_ea)
                xrefs_info.append({
                    "from_ea": xref.from_ea,
                    "type": xref.type.name,
                    "function": func_name,
                })
        except:
            pass

        # Trace caller chains for each xref
        all_chains = []
        functions_involved = set()

        for xref_info in xrefs_info:
            if xref_info["function"]:
                functions_involved.add(xref_info["function"])

            chains = get_caller_chain(xref_info["from_ea"])
            for chain in chains:
                all_chains.append(chain)
                for func_ea, func_name in chain:
                    functions_involved.add(func_name)

        # Add to report for each category
        string_info = {
            "value": content[:100] + ("..." if len(content) > 100 else ""),
            "address": f"0x{string_ea:08X}",
            "xrefs": xrefs_info,
            "caller_chains": all_chains,
            "functions_involved": list(functions_involved),
            "subtypes": [(cat, subtype) for cat, subtype, _ in categories],
        }

        # Add to each matching category
        for category, subtype, _ in categories:
            report[category].append(string_info)

    # Print report grouped by category
    for category in ["Network", "Persistence", "Anti-Debug", "File_Operations", "Crypto"]:
        strings_in_cat = report.get(category, [])
        if not strings_in_cat:
            continue

        print()
        print("=" * 80)
        print(f"CATEGORY: {category}")
        print(f"Total strings: {len(strings_in_cat)}")
        print("=" * 80)

        for i, sinfo in enumerate(strings_in_cat, 1):
            print()
            print(f"  [{i}] String: {sinfo['value']}")
            print(f"      Address: {sinfo['address']}")
            print(f"      Subtypes: {', '.join(f'{cat}:{st}' for cat, st in sinfo['subtypes'])}")

            if sinfo["xrefs"]:
                print(f"      Direct References ({len(sinfo['xrefs'])}):")
                for xref in sinfo["xrefs"][:5]:  # Limit to first 5
                    func_str = xref["function"] if xref["function"] else "<unknown>"
                    print(f"        - 0x{xref['from_ea']:08X} in {func_str} ({xref['type']})")
                if len(sinfo["xrefs"]) > 5:
                    print(f"        ... and {len(sinfo['xrefs']) - 5} more")
            else:
                print("      Direct References: None")

            if sinfo["caller_chains"]:
                print(f"      Call Chains ({len(sinfo['caller_chains'])}):")
                for j, chain in enumerate(sinfo["caller_chains"][:3], 1):  # Limit to first 3 chains
                    chain_str = " <- ".join(f"{name}" for _, name in chain)
                    print(f"        Chain {j}: {chain_str}")
                if len(sinfo["caller_chains"]) > 3:
                    print(f"        ... and {len(sinfo['caller_chains']) - 3} more chains")

            if sinfo["functions_involved"]:
                print(f"      Functions Involved ({len(sinfo['functions_involved'])}): ", end="")
                funcs = list(sinfo["functions_involved"])[:5]
                print(", ".join(funcs), end="")
                if len(sinfo["functions_involved"]) > 5:
                    print(f" ... and {len(sinfo['functions_involved']) - 5} more")
                else:
                    print()

    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total strings analyzed: {string_count}")
    print(f"Interesting strings found: {interesting_count}")
    print()
    print("Strings by category:")
    for category in ["Network", "Persistence", "Anti-Debug", "File_Operations", "Crypto"]:
        count = len(report.get(category, []))
        print(f"  - {category}: {count}")

    # Export as JSON
    json_report = {}
    for category, strings in report.items():
        json_report[category] = []
        for sinfo in strings:
            json_entry = {
                "value": sinfo["value"],
                "address": sinfo["address"],
                "subtypes": sinfo["subtypes"],
                "direct_refs": [
                    {
                        "from": f"0x{x['from_ea']:08X}",
                        "function": x["function"],
                        "type": x["type"]
                    }
                    for x in sinfo["xrefs"]
                ],
                "caller_chains": [
                    [{"ea": f"0x{ea:08X}", "name": name} for ea, name in chain]
                    for chain in sinfo["caller_chains"]
                ],
                "functions_involved": sinfo["functions_involved"],
            }
            json_report[category].append(json_entry)

    print()
    print("=" * 80)
    print("JSON REPORT")
    print("=" * 80)
    print(json.dumps(json_report, indent=2))

# Run the analysis
analyze_strings()

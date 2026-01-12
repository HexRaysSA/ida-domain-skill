#!/usr/bin/env python3
"""
Exercise 18: Binary-to-SARIF Security Audit Export

This script analyzes a binary for security-relevant patterns and exports
findings in SARIF format for integration with other security tools.
"""

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# ============================================================================
# Configuration
# ============================================================================

# Dangerous APIs by category
DANGEROUS_APIS = {
    "buffer_overflow": {
        "apis": ["strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
                 "strncpy", "strncat", "memcpy", "memmove", "wcscpy", "wcscat"],
        "severity": "high",
        "message": "Potential buffer overflow vulnerability",
        "remediation": "Use bounds-checked versions: strncpy_s, strlcpy, snprintf"
    },
    "format_string": {
        "apis": ["printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
                 "vsprintf", "vsnprintf", "syslog", "wprintf"],
        "severity": "high",
        "message": "Potential format string vulnerability",
        "remediation": "Always use format string: printf(\"%s\", user_input)"
    },
    "command_injection": {
        "apis": ["system", "popen", "exec", "execl", "execle", "execlp",
                 "execv", "execve", "execvp", "ShellExecute", "ShellExecuteEx",
                 "WinExec", "CreateProcess", "CreateProcessA", "CreateProcessW"],
        "severity": "critical",
        "message": "Command injection vulnerability",
        "remediation": "Avoid shell execution; use safe alternatives or input validation"
    },
    "memory_unsafe": {
        "apis": ["malloc", "calloc", "realloc", "free", "alloca",
                 "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree"],
        "severity": "medium",
        "message": "Memory management function - verify proper usage",
        "remediation": "Ensure matching alloc/free, check return values, avoid double-free"
    },
    "weak_crypto": {
        "apis": ["MD5", "MD5_Init", "MD5_Update", "MD5_Final",
                 "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final",
                 "DES_ecb_encrypt", "DES_cbc_encrypt", "RC4", "RC2"],
        "severity": "medium",
        "message": "Weak cryptographic algorithm detected",
        "remediation": "Use modern algorithms: SHA-256, AES-GCM, ChaCha20"
    },
    "insecure_random": {
        "apis": ["rand", "srand", "random", "srandom", "rand_r",
                 "drand48", "lrand48", "mrand48"],
        "severity": "medium",
        "message": "Insecure random number generator",
        "remediation": "Use cryptographically secure RNG: CryptGenRandom, /dev/urandom"
    },
    "deprecated_apis": {
        "apis": ["tmpnam", "tempnam", "mktemp", "getwd", "getpass",
                 "crypt", "setjmp", "longjmp"],
        "severity": "low",
        "message": "Deprecated or unsafe API",
        "remediation": "Use modern secure alternatives"
    },
    "network_unsafe": {
        "apis": ["gethostbyname", "gethostbyaddr", "inet_ntoa", "inet_addr"],
        "severity": "low",
        "message": "Thread-unsafe or deprecated network API",
        "remediation": "Use getaddrinfo, getnameinfo, inet_ntop"
    }
}

# Anti-debug APIs
ANTI_DEBUG_APIS = {
    "windows": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "OutputDebugString",
                "GetTickCount", "QueryPerformanceCounter",
                "NtSetInformationThread", "ZwSetInformationThread"],
    "linux": ["ptrace", "prctl"]
}

# Patterns for hardcoded secrets
SECRET_PATTERNS = [
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Possible base64 encoded secret"),
    (r"(?:password|passwd|pwd|secret|api_?key|token)[\s:=]+['\"]?[\w]{4,}", "Hardcoded credential"),
    (r"(?:BEGIN|END)\s+(?:RSA|DSA|EC|OPENSSH)\s+(?:PRIVATE|PUBLIC)\s+KEY", "Embedded cryptographic key"),
    (r"[0-9a-f]{32}", "Possible MD5 hash or hex key"),
    (r"[0-9a-f]{40}", "Possible SHA-1 hash or hex key"),
    (r"[0-9a-f]{64}", "Possible SHA-256 hash or hex key"),
    (r"https?://[^\s]+:[^\s@]+@", "URL with embedded credentials"),
]


@dataclass
class Finding:
    """Represents a security finding."""
    rule_id: str
    category: str
    severity: str  # critical, high, medium, low
    message: str
    ea: int
    function_name: Optional[str] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0

    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def get_function_context(ea: int) -> tuple[Optional[str], Optional[str]]:
    """Get function name and code snippet at address."""
    func = db.functions.get_at(ea)
    func_name = None
    snippet = None

    if func:
        func_name = db.functions.get_name(func)
        try:
            # Try to get pseudocode
            lines = db.functions.get_pseudocode(func)
            if lines:
                snippet = "\n".join(lines[:10])  # First 10 lines
        except:
            try:
                # Fall back to disassembly
                lines = db.functions.get_disassembly(func)
                if lines:
                    snippet = "\n".join(lines[:5])
            except:
                pass

    return func_name, snippet


def find_dangerous_api_usage() -> List[Finding]:
    """Find usage of dangerous APIs in the binary."""
    findings = []

    # Build a map of API addresses
    api_locations = {}

    # Look for imported functions with dangerous names
    for func in db.functions:
        func_name = db.functions.get_name(func)
        if not func_name:
            continue

        # Clean up the name (remove prefixes like j_, __)
        clean_name = func_name.lstrip("_").lstrip("j_").lstrip("_")

        for category, info in DANGEROUS_APIS.items():
            for api in info["apis"]:
                if clean_name == api or clean_name.startswith(api + "@"):
                    api_locations[func.start_ea] = (func_name, category, info)

    # Find all call sites to these APIs
    for api_ea, (api_name, category, info) in api_locations.items():
        # Get all callers
        try:
            for xref in db.xrefs.to_ea(api_ea):
                if xref.is_call:
                    caller_ea = xref.from_ea
                    func_name, snippet = get_function_context(caller_ea)

                    findings.append(Finding(
                        rule_id=f"DANGEROUS_API_{category.upper()}",
                        category=category,
                        severity=info["severity"],
                        message=f"{info['message']}: {api_name}",
                        ea=caller_ea,
                        function_name=func_name,
                        code_snippet=snippet,
                        remediation=info["remediation"],
                        context={"api_name": api_name, "api_address": hex(api_ea)}
                    ))
        except:
            pass

    return findings


def find_anti_debug_techniques() -> List[Finding]:
    """Detect anti-debugging techniques."""
    findings = []

    all_anti_debug = ANTI_DEBUG_APIS["windows"] + ANTI_DEBUG_APIS["linux"]

    for func in db.functions:
        func_name = db.functions.get_name(func)
        if not func_name:
            continue

        clean_name = func_name.lstrip("_").lstrip("j_").lstrip("_")

        if clean_name in all_anti_debug:
            # Find callers of this anti-debug function
            try:
                for xref in db.xrefs.to_ea(func.start_ea):
                    if xref.is_call:
                        caller_name, snippet = get_function_context(xref.from_ea)

                        findings.append(Finding(
                            rule_id="ANTI_DEBUG_API",
                            category="anti_debug",
                            severity="medium",
                            message=f"Anti-debugging technique detected: {func_name}",
                            ea=xref.from_ea,
                            function_name=caller_name,
                            code_snippet=snippet,
                            remediation="Review if anti-debug is legitimate security measure",
                            context={"technique": func_name}
                        ))
            except:
                pass

    return findings


def find_hardcoded_secrets() -> List[Finding]:
    """Find potential hardcoded secrets and high-entropy strings."""
    findings = []

    for s in db.strings:
        try:
            content = str(s)
            address = s.address

            # Skip very short strings
            if len(content) < 8:
                continue

            # Check for secret patterns
            for pattern, description in SECRET_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    func_name, snippet = get_function_context(address)

                    findings.append(Finding(
                        rule_id="HARDCODED_SECRET",
                        category="secrets",
                        severity="critical",
                        message=f"{description}: {content[:50]}...",
                        ea=address,
                        function_name=func_name,
                        code_snippet=snippet,
                        remediation="Move secrets to secure storage, environment variables, or key management system",
                        context={"pattern_matched": description, "string_preview": content[:100]}
                    ))
                    break

            # Check for high entropy (potential crypto keys)
            if len(content) >= 16:
                try:
                    entropy = calculate_entropy(content.encode('utf-8', errors='ignore'))
                    if entropy > 4.5 and len(content) >= 20:
                        # High entropy string - possible key/encrypted data
                        func_name, snippet = get_function_context(address)

                        findings.append(Finding(
                            rule_id="HIGH_ENTROPY_STRING",
                            category="secrets",
                            severity="high",
                            message=f"High entropy string (entropy={entropy:.2f}): {content[:30]}...",
                            ea=address,
                            function_name=func_name,
                            code_snippet=snippet,
                            remediation="Verify this is not a hardcoded encryption key or secret",
                            context={"entropy": entropy, "string_preview": content[:100]}
                        ))
                except:
                    pass

        except Exception as e:
            continue

    return findings


def find_suspicious_strings() -> List[Finding]:
    """Find suspicious strings that might indicate issues."""
    findings = []

    suspicious_patterns = [
        (r"(?:root|admin|administrator)(?:@|:)", "Hardcoded privileged user"),
        (r"(?:mysql|postgres|mongodb|redis)://", "Database connection string"),
        (r"(?:aws|azure|gcp)[_-]?(?:key|secret|token)", "Cloud credentials"),
        (r"bearer\s+[a-zA-Z0-9\-_]+", "Bearer token"),
        (r"(?:ssh|ftp)://", "Protocol with potential credentials"),
    ]

    for s in db.strings:
        try:
            content = str(s).lower()
            address = s.address

            for pattern, description in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    func_name, snippet = get_function_context(address)

                    findings.append(Finding(
                        rule_id="SUSPICIOUS_STRING",
                        category="secrets",
                        severity="high",
                        message=f"{description}: {str(s)[:50]}",
                        ea=address,
                        function_name=func_name,
                        code_snippet=snippet,
                        remediation="Review and remove hardcoded credentials",
                        context={"pattern": description}
                    ))
                    break
        except:
            continue

    return findings


def generate_sarif_report(findings: List[Finding], binary_name: str) -> dict:
    """Generate SARIF 2.1.0 compliant report."""

    # Define rules
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            severity_map = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note"
            }
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("_", " ").title(),
                "shortDescription": {"text": f.category.replace("_", " ").title()},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {
                    "level": severity_map.get(f.severity, "warning")
                },
                "properties": {
                    "category": f.category,
                    "severity": f.severity
                }
            }

    # Generate results
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": binary_name},
                    "address": {
                        "absoluteAddress": f.ea
                    }
                }
            }],
            "properties": {
                "severity": f.severity,
                "category": f.category,
                "address": hex(f.ea)
            }
        }

        if f.function_name:
            result["locations"][0]["logicalLocations"] = [{"name": f.function_name}]

        if f.remediation:
            result["fixes"] = [{"description": {"text": f.remediation}}]

        if f.code_snippet:
            result["codeFlows"] = [{
                "message": {"text": "Code context"},
                "threadFlows": [{
                    "locations": [{
                        "location": {
                            "message": {"text": f.code_snippet[:500]}
                        }
                    }]
                }]
            }]

        if f.context:
            result["properties"].update(f.context)

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IDA Domain Security Scanner",
                    "version": "1.0.0",
                    "informationUri": "https://hex-rays.com",
                    "rules": list(rules.values())
                }
            },
            "artifacts": [{
                "location": {"uri": binary_name},
                "sourceLanguage": "binary"
            }],
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }

    return sarif


def generate_summary(findings: List[Finding]) -> dict:
    """Generate summary statistics."""
    summary = {
        "total_findings": len(findings),
        "by_severity": defaultdict(int),
        "by_category": defaultdict(int),
        "by_rule": defaultdict(int)
    }

    for f in findings:
        summary["by_severity"][f.severity] += 1
        summary["by_category"][f.category] += 1
        summary["by_rule"][f.rule_id] += 1

    # Convert defaultdicts to regular dicts for JSON serialization
    summary["by_severity"] = dict(summary["by_severity"])
    summary["by_category"] = dict(summary["by_category"])
    summary["by_rule"] = dict(summary["by_rule"])

    return summary


# ============================================================================
# Main Analysis
# ============================================================================

print("=" * 70)
print("Binary-to-SARIF Security Audit Export")
print("=" * 70)
print(f"Binary: {db.module}")
print(f"Architecture: {db.architecture} ({db.bitness}-bit)")
print()

# Collect all findings
all_findings = []

print("[*] Scanning for dangerous API usage...")
api_findings = find_dangerous_api_usage()
all_findings.extend(api_findings)
print(f"    Found {len(api_findings)} dangerous API usages")

print("[*] Detecting anti-debug techniques...")
anti_debug_findings = find_anti_debug_techniques()
all_findings.extend(anti_debug_findings)
print(f"    Found {len(anti_debug_findings)} anti-debug techniques")

print("[*] Searching for hardcoded secrets...")
secret_findings = find_hardcoded_secrets()
all_findings.extend(secret_findings)
print(f"    Found {len(secret_findings)} potential secrets")

print("[*] Scanning for suspicious strings...")
suspicious_findings = find_suspicious_strings()
all_findings.extend(suspicious_findings)
print(f"    Found {len(suspicious_findings)} suspicious strings")

print()
print("=" * 70)
print("ANALYSIS SUMMARY")
print("=" * 70)

summary = generate_summary(all_findings)
print(f"Total Findings: {summary['total_findings']}")
print()

print("By Severity:")
for sev in ["critical", "high", "medium", "low"]:
    count = summary["by_severity"].get(sev, 0)
    if count > 0:
        print(f"  {sev.upper():10s}: {count}")

print()
print("By Category:")
for cat, count in sorted(summary["by_category"].items(), key=lambda x: -x[1]):
    print(f"  {cat:20s}: {count}")

print()
print("=" * 70)
print("DETAILED FINDINGS")
print("=" * 70)

# Sort by severity
severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
sorted_findings = sorted(all_findings, key=lambda f: (severity_order.get(f.severity, 4), f.category))

for i, f in enumerate(sorted_findings, 1):
    print()
    print(f"[{i}] {f.severity.upper()} - {f.rule_id}")
    print(f"    Address: 0x{f.ea:08X}")
    print(f"    Function: {f.function_name or 'Unknown'}")
    print(f"    Message: {f.message}")
    if f.remediation:
        print(f"    Remediation: {f.remediation}")

# Generate and save SARIF report
sarif_report = generate_sarif_report(all_findings, db.module)
sarif_path = Path("/Users/plosson/devel/projects/hexrays/ida-domain-skill/results/18_binary_sarif_export/results.sarif")
sarif_path.write_text(json.dumps(sarif_report, indent=2))

print()
print("=" * 70)
print(f"SARIF report saved to: {sarif_path}")
print("=" * 70)

# Output JSON summary for easy parsing
output_summary = {
    "binary": db.module,
    "architecture": db.architecture,
    "bitness": db.bitness,
    "summary": summary,
    "sarif_path": str(sarif_path)
}
print()
print("JSON Summary:")
print(json.dumps(output_summary, indent=2))

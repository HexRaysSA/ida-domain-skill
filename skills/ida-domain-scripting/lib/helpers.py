"""
IDA Domain Helper Utilities

A collection of reusable helper functions for IDA Domain scripting.
These helpers are automatically available in auto-wrapped scripts via `from helpers import *`.

Categories:
    1. Database Helpers - Simplified database access
    2. Function Analysis - Function search and analysis
    3. String Analysis - String search and cross-reference utilities
    4. Byte Patterns - Binary pattern search and detection
    5. Output Formatting - Pretty printing utilities
    6. Report Generation - Export and reporting functions
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_domain.xrefs import XrefInfo

if TYPE_CHECKING:
    from ida_funcs import func_t
    from ida_idaapi import ea_t
    from ida_domain.strings import StringItem


# =============================================================================
# 1. Database Helpers
# =============================================================================


def quick_open(
    path: str,
    save: bool = False,
    auto_analysis: bool = True
) -> Database:
    """
    Simplified database opening with sensible defaults.

    A convenience wrapper around Database.open() that provides a simpler
    interface for common use cases.

    Args:
        path: Path to the binary file or .i64 database.
        save: Whether to save database changes on close. Defaults to False.
        auto_analysis: Whether to run auto-analysis on open. Defaults to True.

    Returns:
        Database: An open database instance. Use as context manager.

    Example:
        ```python
        with quick_open("/path/to/binary.exe") as db:
            for func in db.functions:
                print(db.functions.get_name(func))
        ```
    """
    opts = IdaCommandOptions(auto_analysis=auto_analysis)
    return Database.open(path, opts, save_on_close=save)


def get_db_summary(db: Database) -> Dict[str, Any]:
    """
    Get a summary of database statistics.

    Collects key metrics about the loaded binary including function count,
    string count, segment information, and file metadata.

    Args:
        db: An open Database instance.

    Returns:
        dict: A dictionary containing:
            - module: Module name
            - path: Input file path
            - architecture: Processor architecture
            - bitness: 32 or 64
            - format: File format (PE, ELF, etc.)
            - base_address: Image base address
            - function_count: Total number of functions
            - string_count: Total number of strings
            - segment_count: Total number of segments
            - md5: MD5 hash of input file
            - sha256: SHA256 hash of input file

    Example:
        ```python
        summary = get_db_summary(db)
        print(f"Binary: {summary['module']}")
        print(f"Functions: {summary['function_count']}")
        ```
    """
    summary = {
        "module": db.module,
        "path": db.path,
        "architecture": db.architecture,
        "bitness": db.bitness,
        "format": db.format,
        "base_address": format_address(db.base_address) if db.base_address else None,
        "function_count": len(db.functions),
        "string_count": len(db.strings),
        "segment_count": len(list(db.segments)),
        "md5": db.md5,
        "sha256": db.sha256,
    }
    return summary


# =============================================================================
# 2. Function Analysis
# =============================================================================


def find_functions_by_pattern(
    db: Database,
    pattern: str,
    case_sensitive: bool = False
) -> List[Tuple['func_t', str]]:
    """
    Find functions whose names match a regex pattern.

    Searches through all function names in the database and returns
    those matching the provided regular expression.

    Args:
        db: An open Database instance.
        pattern: Regular expression pattern to match against function names.
        case_sensitive: Whether the match should be case-sensitive. Defaults to False.

    Returns:
        list: List of tuples (func_t, name) for matching functions.

    Example:
        ```python
        # Find all functions starting with 'sub_'
        funcs = find_functions_by_pattern(db, r'^sub_')

        # Find functions containing 'crypt' (case-insensitive)
        funcs = find_functions_by_pattern(db, r'crypt')
        ```
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    regex = re.compile(pattern, flags)
    results = []

    for func in db.functions:
        name = db.functions.get_name(func)
        if name and regex.search(name):
            results.append((func, name))

    return results


def get_function_callers(db: Database, func: 'func_t') -> List['func_t']:
    """
    Get all functions that call this function.

    Analyzes cross-references to find all functions containing
    call instructions that target the specified function.

    Args:
        db: An open Database instance.
        func: The function to find callers for.

    Returns:
        list: List of func_t objects that call this function.

    Example:
        ```python
        func = db.functions.get_function_by_name("malloc")
        if func:
            callers = get_function_callers(db, func)
            print(f"malloc is called by {len(callers)} functions")
        ```
    """
    return db.functions.get_callers(func)


def get_function_callees(db: Database, func: 'func_t') -> List['func_t']:
    """
    Get all functions called by this function.

    Analyzes the function's instructions to find all call targets
    and returns the corresponding function objects.

    Args:
        db: An open Database instance.
        func: The function to find callees for.

    Returns:
        list: List of func_t objects called by this function.

    Example:
        ```python
        func = db.functions.get_function_by_name("main")
        if func:
            callees = get_function_callees(db, func)
            for callee in callees:
                print(f"  calls {db.functions.get_name(callee)}")
        ```
    """
    return db.functions.get_callees(func)


def decompile_function(db: Database, func: 'func_t') -> Optional[str]:
    """
    Get the decompiled pseudocode of a function as a single string.

    Uses the Hex-Rays decompiler to generate human-readable C-like
    pseudocode for the given function.

    Args:
        db: An open Database instance.
        func: The function to decompile.

    Returns:
        str: The decompiled pseudocode as a string, or None if decompilation fails.

    Example:
        ```python
        func = db.functions.get_function_by_name("main")
        if func:
            code = decompile_function(db, func)
            if code:
                print(code)
        ```
    """
    try:
        lines = db.functions.get_pseudocode(func)
        return "\n".join(lines)
    except RuntimeError:
        return None


def get_function_complexity(db: Database, func: 'func_t') -> Dict[str, int]:
    """
    Calculate complexity metrics for a function.

    Computes several complexity indicators:
    - Basic block count
    - Edge count (control flow transitions)
    - Cyclomatic complexity (McCabe's metric)
    - Instruction count

    Args:
        db: An open Database instance.
        func: The function to analyze.

    Returns:
        dict: Dictionary containing:
            - basic_block_count: Number of basic blocks
            - edge_count: Number of control flow edges
            - cyclomatic_complexity: McCabe's cyclomatic complexity (E - N + 2)
            - instruction_count: Total number of instructions

    Example:
        ```python
        func = db.functions.get_function_by_name("complex_algorithm")
        if func:
            metrics = get_function_complexity(db, func)
            print(f"Cyclomatic complexity: {metrics['cyclomatic_complexity']}")
        ```
    """
    flowchart = db.functions.get_flowchart(func)
    if not flowchart:
        return {
            "basic_block_count": 0,
            "edge_count": 0,
            "cyclomatic_complexity": 0,
            "instruction_count": 0,
        }

    basic_block_count = len(flowchart)
    edge_count = 0
    instruction_count = 0

    for block in flowchart:
        edge_count += block.count_successors()
        instructions = block.get_instructions()
        if instructions:
            instruction_count += sum(1 for _ in instructions)

    # McCabe's cyclomatic complexity: E - N + 2
    # Where E = edges, N = nodes (basic blocks)
    cyclomatic_complexity = edge_count - basic_block_count + 2

    return {
        "basic_block_count": basic_block_count,
        "edge_count": edge_count,
        "cyclomatic_complexity": cyclomatic_complexity,
        "instruction_count": instruction_count,
    }


# =============================================================================
# 3. String Analysis
# =============================================================================


# Default keywords for interesting string detection
DEFAULT_INTERESTING_KEYWORDS = [
    # Credentials and authentication
    "password", "passwd", "pwd", "secret", "credential", "auth", "token",
    "api_key", "apikey", "private_key", "privatekey",
    # URLs and network
    "http://", "https://", "ftp://", "file://", "\\\\\\\\",
    # File paths
    "/etc/", "/tmp/", "/var/", "C:\\\\", ":\\\\",
    # Commands and shell
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "system(",
    # Debug and error strings
    "debug", "error", "failed", "exception", "stack trace",
    # Encryption
    "encrypt", "decrypt", "cipher", "aes", "rsa", "des",
    # Registry (Windows)
    "HKEY_", "SOFTWARE\\\\", "CurrentVersion",
]


def find_interesting_strings(
    db: Database,
    keywords: Optional[List[str]] = None
) -> List[Tuple['StringItem', str]]:
    """
    Find strings that might be security-relevant or interesting.

    Searches for strings containing common patterns like passwords,
    URLs, file paths, commands, and other potentially interesting content.

    Args:
        db: An open Database instance.
        keywords: Optional list of keywords to search for. If None, uses
            a default set of security-relevant patterns.

    Returns:
        list: List of tuples (StringItem, matched_keyword) for each match.

    Example:
        ```python
        # Use default keywords
        interesting = find_interesting_strings(db)
        for string_item, keyword in interesting:
            print(f"Found '{keyword}' at {format_address(string_item.address)}")

        # Custom keywords
        interesting = find_interesting_strings(db, ["config", "license"])
        ```
    """
    if keywords is None:
        keywords = DEFAULT_INTERESTING_KEYWORDS

    results = []
    for string_item in db.strings:
        try:
            string_value = str(string_item).lower()
            for keyword in keywords:
                if keyword.lower() in string_value:
                    results.append((string_item, keyword))
                    break  # Only match once per string
        except (UnicodeDecodeError, AttributeError):
            continue

    return results


def get_string_xrefs(
    db: Database,
    string_addr: 'ea_t'
) -> List[Tuple['ea_t', Optional['func_t']]]:
    """
    Find all cross-references to a string address.

    Returns a list of addresses that reference the string, along with
    the containing function (if any).

    Args:
        db: An open Database instance.
        string_addr: The address of the string.

    Returns:
        list: List of tuples (xref_address, containing_function).
            The function may be None if the xref is outside any function.

    Example:
        ```python
        for string_item in db.strings:
            xrefs = get_string_xrefs(db, string_item.address)
            for from_ea, containing_func in xrefs:
                func_name = db.functions.get_name(containing_func) if containing_func else "N/A"
                print(f"Referenced from {format_address(from_ea)} in {func_name}")
        ```
    """
    results = []
    for xref in db.xrefs.to_ea(string_addr):
        func = db.functions.get_at(xref.from_ea)
        results.append((xref.from_ea, func))
    return results


def search_strings(
    db: Database,
    pattern: str,
    case_sensitive: bool = False
) -> List['StringItem']:
    """
    Search for strings matching a regex pattern.

    Args:
        db: An open Database instance.
        pattern: Regular expression pattern to match.
        case_sensitive: Whether the match should be case-sensitive. Defaults to False.

    Returns:
        list: List of StringItem objects whose content matches the pattern.

    Example:
        ```python
        # Find all IP addresses
        ip_strings = search_strings(db, r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}')

        # Find URLs
        url_strings = search_strings(db, r'https?://[\\w./]+')
        ```
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    regex = re.compile(pattern, flags)
    results = []

    for string_item in db.strings:
        try:
            string_value = str(string_item)
            if regex.search(string_value):
                results.append(string_item)
        except (UnicodeDecodeError, AttributeError):
            continue

    return results


# =============================================================================
# 4. Byte Patterns
# =============================================================================


def find_pattern(
    db: Database,
    pattern: Union[bytes, str],
    start_ea: Optional['ea_t'] = None,
    end_ea: Optional['ea_t'] = None
) -> List['ea_t']:
    """
    Find all occurrences of a byte pattern.

    Searches for a binary pattern throughout the database or within
    a specified address range.

    Args:
        db: An open Database instance.
        pattern: Byte pattern as bytes or hex string (e.g., "90 90 90" or b"\\x90\\x90\\x90").
        start_ea: Start address for search. Defaults to database minimum.
        end_ea: End address for search. Defaults to database maximum.

    Returns:
        list: List of addresses where the pattern was found.

    Example:
        ```python
        # Search for NOP sled
        nops = find_pattern(db, b"\\x90\\x90\\x90\\x90\\x90")

        # Search using hex string (spaces optional)
        pattern_addrs = find_pattern(db, "48 89 E5")  # mov rbp, rsp
        ```
    """
    # Convert hex string to bytes if needed
    if isinstance(pattern, str):
        try:
            pattern = bytes.fromhex(pattern.replace(" ", ""))
        except ValueError as e:
            raise ValueError(f"Invalid hex pattern: {pattern}") from e

    return db.bytes.find_binary_sequence(pattern, start_ea, end_ea)


# Known cryptographic constants
CRYPTO_CONSTANTS = {
    # AES S-box (first 16 bytes)
    "AES_SBOX": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    # AES inverse S-box (first 16 bytes)
    "AES_INV_SBOX": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                           0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
    # SHA-256 initial hash values (first constant)
    "SHA256_H": bytes([0x6A, 0x09, 0xE6, 0x67]),
    # SHA-256 round constants (first constant, big-endian)
    "SHA256_K": bytes([0x42, 0x8A, 0x2F, 0x98]),
    # MD5 sine table (first constant, little-endian)
    "MD5_SINE": bytes([0x78, 0xA4, 0x6A, 0xD7]),
    # RSA/crypto marker strings
    "RSA_MARKER": b"-----BEGIN RSA",
    "PEM_MARKER": b"-----BEGIN",
    # RC4 initial permutation marker (0x00 through 0x0F)
    "RC4_SBOX": bytes(range(16)),
    # DES permutation (first 8 bytes of initial permutation table)
    "DES_IP": bytes([58, 50, 42, 34, 26, 18, 10, 2]),
    # Blowfish P-array (first constant)
    "BLOWFISH_P": bytes([0x24, 0x3F, 0x6A, 0x88]),
    # CRC32 polynomial (little-endian)
    "CRC32_POLY": bytes([0x96, 0x30, 0x07, 0x77]),
}


def find_crypto_constants(db: Database) -> Dict[str, List['ea_t']]:
    """
    Search for known cryptographic constants in the binary.

    Looks for byte sequences commonly associated with cryptographic
    algorithms like AES, SHA-256, MD5, RSA, RC4, DES, and Blowfish.

    Args:
        db: An open Database instance.

    Returns:
        dict: Dictionary mapping constant names to lists of addresses
            where they were found.

    Example:
        ```python
        crypto = find_crypto_constants(db)
        for name, addresses in crypto.items():
            if addresses:
                print(f"{name} found at {[format_address(a) for a in addresses]}")
        ```
    """
    results = {}
    for name, pattern in CRYPTO_CONSTANTS.items():
        addresses = find_pattern(db, pattern)
        if addresses:
            results[name] = addresses
    return results


# Architecture-specific function prologues
FUNCTION_PROLOGUES = {
    "x86": [
        b"\x55\x8B\xEC",          # push ebp; mov ebp, esp
        b"\x55\x89\xE5",          # push ebp; mov ebp, esp (AT&T)
        b"\x8B\xFF\x55\x8B\xEC",  # mov edi, edi; push ebp; mov ebp, esp (hotpatch)
    ],
    "x64": [
        b"\x48\x89\x5C\x24",      # mov [rsp+...], rbx
        b"\x48\x83\xEC",          # sub rsp, imm8
        b"\x55\x48\x89\xE5",      # push rbp; mov rbp, rsp
        b"\x40\x55",              # rex push rbp
    ],
    "arm": [
        b"\x04\xE0\x2D\xE5",      # str lr, [sp, #-4]!
        b"\x00\x48\x2D\xE9",      # push {fp, lr}
    ],
    "arm64": [
        b"\xFD\x7B\xBF\xA9",      # stp x29, x30, [sp, #-16]!
        b"\xFD\x03\x00\x91",      # mov x29, sp
    ],
}


def find_function_prologues(
    db: Database,
    architecture: Optional[str] = None
) -> List['ea_t']:
    """
    Find function prologues based on architecture-specific patterns.

    Searches for common function entry point byte sequences that
    indicate the start of a function.

    Args:
        db: An open Database instance.
        architecture: Target architecture ("x86", "x64", "arm", "arm64").
            If None, auto-detects from database metadata.

    Returns:
        list: List of addresses where function prologues were found.

    Example:
        ```python
        # Auto-detect architecture
        prologues = find_function_prologues(db)

        # Specify architecture
        prologues = find_function_prologues(db, "x64")

        # Check for undiscovered functions
        known_funcs = {func.start_ea for func in db.functions}
        undiscovered = [p for p in prologues if p not in known_funcs]
        print(f"Found {len(undiscovered)} potential undiscovered functions")
        ```
    """
    if architecture is None:
        # Auto-detect from database
        arch = db.architecture
        bitness = db.bitness
        if arch:
            arch_lower = arch.lower()
            if "arm" in arch_lower:
                architecture = "arm64" if bitness == 64 else "arm"
            elif "metapc" in arch_lower or "pc" in arch_lower:
                architecture = "x64" if bitness == 64 else "x86"
            else:
                architecture = "x64" if bitness == 64 else "x86"
        else:
            architecture = "x86"  # Default fallback

    patterns = FUNCTION_PROLOGUES.get(architecture, FUNCTION_PROLOGUES["x86"])
    results = []

    for pattern in patterns:
        addresses = find_pattern(db, pattern)
        results.extend(addresses)

    # Remove duplicates and sort
    return sorted(set(results))


# =============================================================================
# 5. Output Formatting
# =============================================================================


def format_function(db: Database, func: 'func_t') -> str:
    """
    Format a function for pretty printing.

    Creates a human-readable string representation of a function
    including its name, address range, and size.

    Args:
        db: An open Database instance.
        func: The function to format.

    Returns:
        str: Formatted string like "main @ 0x00401000 - 0x00401100 (256 bytes)"

    Example:
        ```python
        for func in db.functions:
            print(format_function(db, func))
        ```
    """
    name = db.functions.get_name(func) or "<unnamed>"
    start = format_address(func.start_ea)
    end = format_address(func.end_ea)
    size = func.end_ea - func.start_ea
    return f"{name} @ {start} - {end} ({size} bytes)"


def format_xref(xref: XrefInfo) -> str:
    """
    Format a cross-reference for pretty printing.

    Args:
        xref: The XrefInfo object to format.

    Returns:
        str: Formatted string like "0x00401000 -> 0x00402000 (CALL_NEAR)"

    Example:
        ```python
        for xref in db.xrefs.to_ea(func.start_ea):
            print(format_xref(xref))
        ```
    """
    from_addr = format_address(xref.from_ea)
    to_addr = format_address(xref.to_ea)
    type_name = xref.type.name if hasattr(xref.type, 'name') else str(xref.type)
    return f"{from_addr} -> {to_addr} ({type_name})"


def format_address(ea: Optional['ea_t']) -> str:
    """
    Format an address as a hex string.

    Args:
        ea: The effective address to format. Can be None.

    Returns:
        str: Formatted address like "0x00401000" or "None" if ea is None.

    Example:
        ```python
        addr = format_address(func.start_ea)
        print(f"Function starts at {addr}")
        ```
    """
    if ea is None:
        return "None"
    return f"0x{ea:08X}"


def print_table(headers: List[str], rows: List[List[Any]]) -> None:
    """
    Print data as an aligned table.

    Automatically calculates column widths and prints a nicely
    formatted ASCII table.

    Args:
        headers: List of column header strings.
        rows: List of row data (each row is a list of values).

    Example:
        ```python
        headers = ["Name", "Address", "Size"]
        rows = []
        for func in db.functions:
            name = db.functions.get_name(func)
            rows.append([name, format_address(func.start_ea), func.end_ea - func.start_ea])
        print_table(headers, rows)
        ```
    """
    if not headers:
        return

    # Convert all values to strings
    str_rows = [[str(cell) for cell in row] for row in rows]

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))

    # Create format string
    format_str = " | ".join(f"{{:<{w}}}" for w in widths)
    separator = "-+-".join("-" * w for w in widths)

    # Print table
    print(format_str.format(*headers))
    print(separator)
    for row in str_rows:
        # Pad row if needed
        padded_row = row + [""] * (len(headers) - len(row))
        print(format_str.format(*padded_row[:len(headers)]))


# =============================================================================
# 6. Report Generation
# =============================================================================


def generate_summary_report(db: Database) -> str:
    """
    Generate a Markdown-formatted summary report of the binary.

    Creates a comprehensive report including:
    - File metadata
    - Function statistics
    - String analysis
    - Import/export information

    Args:
        db: An open Database instance.

    Returns:
        str: Markdown-formatted report string.

    Example:
        ```python
        report = generate_summary_report(db)
        print(report)
        # Or save to file:
        Path("report.md").write_text(report)
        ```
    """
    summary = get_db_summary(db)
    lines = []

    # Header
    lines.append(f"# Binary Analysis Report: {summary['module'] or 'Unknown'}")
    lines.append("")

    # File Information
    lines.append("## File Information")
    lines.append("")
    lines.append(f"- **Path**: {summary['path'] or 'N/A'}")
    lines.append(f"- **Architecture**: {summary['architecture'] or 'N/A'}")
    lines.append(f"- **Bitness**: {summary['bitness'] or 'N/A'}-bit")
    lines.append(f"- **Format**: {summary['format'] or 'N/A'}")
    lines.append(f"- **Base Address**: {summary['base_address'] or 'N/A'}")
    lines.append(f"- **MD5**: {summary['md5'] or 'N/A'}")
    lines.append(f"- **SHA256**: {summary['sha256'] or 'N/A'}")
    lines.append("")

    # Statistics
    lines.append("## Statistics")
    lines.append("")
    lines.append(f"- **Functions**: {summary['function_count']}")
    lines.append(f"- **Strings**: {summary['string_count']}")
    lines.append(f"- **Segments**: {summary['segment_count']}")
    lines.append("")

    # Top Functions by Size
    lines.append("## Largest Functions")
    lines.append("")
    func_sizes = []
    for func in db.functions:
        name = db.functions.get_name(func)
        size = func.end_ea - func.start_ea
        func_sizes.append((name, func.start_ea, size))

    func_sizes.sort(key=lambda x: x[2], reverse=True)
    lines.append("| Name | Address | Size |")
    lines.append("|------|---------|------|")
    for name, addr, size in func_sizes[:10]:
        lines.append(f"| {name} | {format_address(addr)} | {size} bytes |")
    lines.append("")

    # Interesting Strings (limited)
    interesting = find_interesting_strings(db)
    if interesting:
        lines.append("## Potentially Interesting Strings")
        lines.append("")
        lines.append("| Address | Keyword | String |")
        lines.append("|---------|---------|--------|")
        for string_item, keyword in interesting[:20]:
            addr = format_address(string_item.address)
            try:
                content = str(string_item)[:50]  # Truncate long strings
                if len(str(string_item)) > 50:
                    content += "..."
                # Escape pipe characters for markdown
                content = content.replace("|", "\\|")
            except (UnicodeDecodeError, AttributeError):
                content = "<decode error>"
            lines.append(f"| {addr} | {keyword} | {content} |")
        if len(interesting) > 20:
            lines.append(f"\n*...and {len(interesting) - 20} more*")
        lines.append("")

    return "\n".join(lines)


def export_functions_json(db: Database, path: Union[str, Path]) -> int:
    """
    Export all functions to a JSON file.

    Creates a JSON file containing detailed information about each
    function in the database.

    Args:
        db: An open Database instance.
        path: Output file path.

    Returns:
        int: Number of functions exported.

    Example:
        ```python
        count = export_functions_json(db, "/tmp/functions.json")
        print(f"Exported {count} functions")
        ```
    """
    functions = []
    for func in db.functions:
        name = db.functions.get_name(func)
        func_data = {
            "name": name,
            "start_ea": func.start_ea,
            "end_ea": func.end_ea,
            "size": func.end_ea - func.start_ea,
            "start_ea_hex": format_address(func.start_ea),
            "end_ea_hex": format_address(func.end_ea),
        }

        # Add complexity metrics
        try:
            complexity = get_function_complexity(db, func)
            func_data["complexity"] = complexity
        except Exception:
            pass

        # Add caller/callee counts
        try:
            func_data["caller_count"] = len(get_function_callers(db, func))
            func_data["callee_count"] = len(get_function_callees(db, func))
        except Exception:
            pass

        functions.append(func_data)

    output = {
        "module": db.module,
        "function_count": len(functions),
        "functions": functions,
    }

    path = Path(path)
    path.write_text(json.dumps(output, indent=2))

    return len(functions)


def export_strings_json(db: Database, path: Union[str, Path]) -> int:
    """
    Export all strings to a JSON file.

    Creates a JSON file containing all extracted strings with their
    addresses and cross-reference information.

    Args:
        db: An open Database instance.
        path: Output file path.

    Returns:
        int: Number of strings exported.

    Example:
        ```python
        count = export_strings_json(db, "/tmp/strings.json")
        print(f"Exported {count} strings")
        ```
    """
    strings = []
    for string_item in db.strings:
        try:
            content = str(string_item)
        except (UnicodeDecodeError, AttributeError):
            content = None

        string_data = {
            "address": string_item.address,
            "address_hex": format_address(string_item.address),
            "length": string_item.length,
            "encoding": string_item.encoding,
            "content": content,
        }

        # Add xref count
        try:
            xrefs = get_string_xrefs(db, string_item.address)
            string_data["xref_count"] = len(xrefs)
        except Exception:
            pass

        strings.append(string_data)

    output = {
        "module": db.module,
        "string_count": len(strings),
        "strings": strings,
    }

    path = Path(path)
    path.write_text(json.dumps(output, indent=2))

    return len(strings)


# =============================================================================
# Export all public functions
# =============================================================================

__all__ = [
    # Database Helpers
    "quick_open",
    "get_db_summary",
    # Function Analysis
    "find_functions_by_pattern",
    "get_function_callers",
    "get_function_callees",
    "decompile_function",
    "get_function_complexity",
    # String Analysis
    "find_interesting_strings",
    "get_string_xrefs",
    "search_strings",
    # Byte Patterns
    "find_pattern",
    "find_crypto_constants",
    "find_function_prologues",
    # Output Formatting
    "format_function",
    "format_xref",
    "format_address",
    "print_table",
    # Report Generation
    "generate_summary_report",
    "export_functions_json",
    "export_strings_json",
]

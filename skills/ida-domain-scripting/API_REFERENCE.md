# IDA Domain API

> IDA Domain API - Python interface for IDA Pro reverse engineering platform

This is a pure python package built on top of IDA Python SDK.
It provides easy access to the main entities manipulated by IDA Pro. All entities are accessible trough the db handle.

# Installation

# IDA Domain API

The IDA Domain API is a new open-source Python API designed to make scripting in IDA simpler, more consistent, and more natural.

This is a first step in a much longer journey. It’s not the finish line, but a foundation for ongoing collaboration between Hex-Rays and the reverse engineering community. Over time, the Domain API will expand to cover more areas of IDA, gradually becoming the main entry point for scripting and plugin development.

The **Domain** in Domain API refers to the domain of reverse engineering. Concepts like functions, types, cross-references, and more are first-class citizens in this API, giving you cleaner, domain-focused abstractions for common tasks.

The Domain API sits on top of the IDA Python SDK, complementing it rather than replacing it. You can use both side by side—combining the clarity and simplicity of Domain API calls with the full flexibility of the SDK when needed.

> **Compatibility:** Requires IDA Pro 9.1.0 or later

## 🚀 Key Features

- **Domain-focused design** – Work directly with core reverse engineering concepts like functions, types, and xrefs as first-class citizens.
- **Open source from day one** – Read the code, suggest improvements, or contribute new ideas.
- **Pure Python implementation** – No compilation required, works with modern Python versions.
- **Compatible by design** – Use alongside the IDA Python SDK without conflicts.
- **Developer-centric** – Reduce boilerplate and streamline frequent tasks.
- **Independently versioned** – Upgrade at your own pace and pin versions for stability.
- **Simple installation** – Get started with a single `pip install`.

## ⚙️ Quick Example

```
import argparse

from ida_domain import Database

parser = argparse.ArgumentParser(description='Quick Usage Example')
parser.add_argument('-f', '--input-file', type=str, required=True)
args = parser.parse_args()

# Open any binary format IDA supports
with Database() as db:
    if db.open(args.input_file):
        # Pythonic iteration over functions
        for func in db.functions:
            print(f'{func.name}: {len(list(db.functions.get_instructions(func)))} instructions')

```

## 📖 Documentation

- **[Getting Started](getting_started/)** - Installation and your first script
- **[Examples](examples/)** - Practical examples for common tasks
- **[API Reference](usage/)** - Complete API documentation

## 🔗 Additional Resources

- **PyPI Package**: [ida-domain on PyPI](https://pypi.org/project/ida-domain/)
- **Source Code**: [GitHub Repository](https://github.com/HexRaysSA/ida-domain)
- **Issues**: [Bug Reports](https://github.com/HexRaysSA/ida-domain/issues)
- **License**: MIT License
# Usage

Welcome to the IDA Domain API reference documentation. This section provides comprehensive documentation for all modules and functions available in the IDA Domain library.

The IDA Domain API is organized around the following top level entities:

- **[Database](../ref/database/)** - Main database operations and management
- **[Entries](../ref/entries/)** - Entry point management and analysis
- **[Segments](../ref/segments/)** - Memory segment operations
- **[Functions](../ref/functions/)** - Function analysis and manipulation
- **[Flowchart](../ref/flowchart/)** - Control flow graph and basic blocks operations
- **[Instructions](../ref/instructions/)** - Instruction-level analysis
- **[Operands](../ref/operands/)** - Operand analysis and manipulation
- **[Bytes](../ref/bytes/)** - Raw byte manipulation and analysis
- **[Strings](../ref/strings/)** - String detection and analysis
- **[Types](../ref/types/)** - Type information and management
- **[Heads](../ref/heads/)** - Address head management
- **[Hooks](../ref/hooks/)** - Hooks / event handling
- **[XRefs](../ref/xrefs/)** - Xref analysis
- **[Names](../ref/names/)** - Symbol name management
- **[Comments](../ref/comments/)** - Comment management
- **[Signature Files](../ref/signature_files/)** - FLIRT signature file operations

## Accessing the entities

The first thing that you will usually want to do is opening a **[Database](../ref/database/)**.

Once the database is opened, you can access all other entities from the database handle itself through their respective property.

```
db = Database()
db.open('/path/to/your/database.idb')
db.functions.get_all()
db.segments.get_all()
db.entries.get_all()
...

```

## Compatibility with IDA Python SDK

The IDA Domain API is fully compatible with the IDA Python SDK shipped with IDA. It means the while we are extending the coverage of IDA Domain API, you can always fallback to using the IDA Python SDK.

Here is an example:

```
import ida_domain
import ida_funcs

db = ida_domain.Database()
db.open('/path/to/your/database.idb')
for i, func in enumerate(db.functions.get_all()):
    print(ida_funcs.get_func_name(func.start_ea)) # <== this is calling IDA Python SDK

```
# Examples

# Examples

This section provides few examples of using the IDA Domain API for common reverse engineering tasks.

## Basic Database Operations

### Opening and Exploring a Database

```
"""
Database exploration example for IDA Domain API.

This example demonstrates how to open an IDA database and explore its basic properties.
"""

import argparse
from dataclasses import asdict

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def explore_database(db_path):
    """Explore basic database information."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(db_path, ida_options) as db:
        # Get basic information
        print(f'Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

        # Get metadata
        print('Database metadata:')
        metadata_dict = asdict(db.metadata)
        for key, value in metadata_dict.items():
            print(f'  {key}: {value}')

        # Count functions
        function_count = 0
        for _ in db.functions:
            function_count += 1
        print(f'Total functions: {function_count}')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    explore_database(args.input_file)


if __name__ == '__main__':
    main()

```

### Complete Traversal of a Database

This example demonstrates a complete traversal of a database:

```
#!/usr/bin/env python3
"""
Database Traversal Example for IDA Domain API

This example demonstrates how to systematically traverse an IDA database and
examine available entities. It provides a structured approach to exploring
contents of a binary analysis database.
"""

import argparse
from dataclasses import asdict

import ida_domain
import ida_domain.flowchart
from ida_domain.database import IdaCommandOptions


def print_section_header(title: str, char: str = '=') -> None:
    """Print a formatted section header for better output organization."""
    print(f'\n{char * 60}')
    print(f' {title}')
    print(f'{char * 60}')


def print_subsection_header(title: str) -> None:
    """Print a formatted subsection header."""
    print(f'\n--- {title} ---')


def traverse_metadata(db: ida_domain.Database) -> None:
    """
    Traverse and display database metadata.

    Args:
        db: The IDA database instance
    """
    print_section_header('DATABASE METADATA')

    metadata = asdict(db.metadata)
    if metadata:
        for key, value in metadata.items():
            print(f'  {key:15}: {value}')
    else:
        print('  No metadata available')

    # Additional database properties
    print(f'  {"current_ea":15}: 0x{db.current_ea:x}')
    print(f'  {"minimum_ea":15}: 0x{db.minimum_ea:x}')
    print(f'  {"maximum_ea":15}: 0x{db.maximum_ea:x}')


def traverse_segments(db: ida_domain.Database) -> None:
    """
    Traverse and display memory segments.

    Args:
        db: The IDA database instance
    """
    print_section_header('MEMORY SEGMENTS')

    segments = list(db.segments)
    print(f'Total segments: {len(segments)}')

    for i, segment in enumerate(segments, 1):
        print(
            f'  [{i:2d}] {segment.name:20} | '
            f'Start: 0x{segment.start_ea:08x} | '
            f'End: 0x{segment.end_ea:08x} | '
            f'Size: {segment.size} | '
            f'Type: {segment.type}'
        )


def traverse_functions(db: ida_domain.Database) -> None:
    """
    Traverse and display functions.

    Args:
        db: The IDA database instance
    """
    print_section_header('FUNCTIONS')

    functions = list(db.functions)
    print(f'Total functions: {len(functions)}')

    # Show first 20 functions to avoid overwhelming output
    display_count = min(20, len(functions))
    if display_count < len(functions):
        print(f'Displaying first {display_count} functions:')

    for i, func in enumerate(functions[:display_count], 1):
        print(
            f'  [{i:2d}] {func.name:30} | '
            f'Start: 0x{func.start_ea:08x} | '
            f'End: 0x{func.end_ea:08x} | '
            f'Size: {func.size}'
        )

    if display_count < len(functions):
        print(f'  ... and {len(functions) - display_count} more functions')


def traverse_entries(db: ida_domain.Database) -> None:
    """
    Traverse and display program entries.

    Args:
        db: The IDA database instance
    """
    print_section_header('PROGRAM ENTRIES')

    entries = list(db.entries)
    print(f'Total entries: {len(entries)}')

    for i, entry in enumerate(entries, 1):
        print(
            f'  [{i:2d}] {entry.name:30} | '
            f'Address: 0x{entry.address:08x} | '
            f'Ordinal: {entry.ordinal}'
        )


def traverse_heads(db: ida_domain.Database) -> None:
    """
    Traverse and display heads (data and code locations).

    Args:
        db: The IDA database instance
    """
    print_section_header('HEADS (Data/Code Locations)')

    heads = list(db.heads)
    print(f'Total heads: {len(heads)}')

    # Show first 20 heads to avoid overwhelming output
    display_count = min(20, len(heads))
    if display_count < len(heads):
        print(f'Displaying first {display_count} heads:')

    for i, head in enumerate(heads[:display_count], 1):
        print(f'  [{i:2d}] Address: 0x{head:08x}')

    if display_count < len(heads):
        print(f'  ... and {len(heads) - display_count} more heads')


def traverse_strings(db: ida_domain.Database) -> None:
    """
    Traverse and display identified strings.

    Args:
        db: The IDA database instance
    """
    print_section_header('STRINGS')

    strings = list(db.strings)
    print(f'Total strings: {len(strings)}')

    # Show first 15 strings to avoid overwhelming output
    display_count = min(15, len(strings))
    if display_count < len(strings):
        print(f'Displaying first {display_count} strings:')

    for i, item in enumerate(strings[:display_count], 1):
        # Truncate very long strings for display
        display_str = str(item)[:50] + '...' if len(str(item)) > 50 else str(i)
        print(f'  [{i:2d}] 0x{item.address:08x}: "{display_str}"')

    if display_count < len(strings):
        print(f'  ... and {len(strings) - display_count} more strings')


def traverse_names(db: ida_domain.Database) -> None:
    """
    Traverse and display names (symbols and labels).

    Args:
        db: The IDA database instance
    """
    print_section_header('NAMES (Symbols & Labels)')

    names = list(db.names)
    print(f'Total names: {len(names)}')

    # Show first 20 names to avoid overwhelming output
    display_count = min(20, len(names))
    if display_count < len(names):
        print(f'Displaying first {display_count} names:')

    for i, (ea, name) in enumerate(names[:display_count], 1):
        print(f'  [{i:2d}] 0x{ea:08x}: {name}')

    if display_count < len(names):
        print(f'  ... and {len(names) - display_count} more names')


def traverse_types(db: ida_domain.Database) -> None:
    """
    Traverse and display type definitions.

    Args:
        db: The IDA database instance
    """
    print_section_header('TYPE DEFINITIONS')

    types = list(db.types)
    print(f'Total types: {len(types)}')

    # Show first 15 types to avoid overwhelming output
    display_count = min(15, len(types))
    if display_count < len(types):
        print(f'Displaying first {display_count} types:')

    for i, type_def in enumerate(types[:display_count], 1):
        type_name = (
            type_def.get_type_name()
            if type_def.get_type_name()
            else f'<unnamed_{type_def.get_tid()}>'
        )
        print(f'  [{i:2d}] {type_name:30} | TID: {type_def.get_tid()}')

    if display_count < len(types):
        print(f'  ... and {len(types) - display_count} more types')


def traverse_comments(db: ida_domain.Database) -> None:
    """
    Traverse and display comments.

    Args:
        db: The IDA database instance
    """
    print_section_header('COMMENTS')

    # Get all comments (regular and repeatable)
    comments = list(db.comments)
    print(f'Total comments: {len(comments)}')

    # Show first 10 comments to avoid overwhelming output
    display_count = min(10, len(comments))
    if display_count < len(comments):
        print(f'Displaying first {display_count} comments:')

    for i, info in enumerate(comments[:display_count], 1):
        # Truncate very long comments for display
        text = info.comment[:60] + '...' if len(info.comment) > 60 else info.comment
        type = 'REP' if info.repeatable else 'REG'
        print(f'  [{i:2d}] 0x{info.ea:08x} [{type}]: {text}')

    if display_count < len(comments):
        print(f'  ... and {len(comments) - display_count} more comments')


def traverse_basic_blocks(db: ida_domain.Database) -> None:
    """
    Traverse and display basic blocks.

    Args:
        db: The IDA database instance
    """
    print_section_header('BASIC BLOCKS')

    flowchart = ida_domain.flowchart.FlowChart(db, None, (db.minimum_ea, db.maximum_ea))
    basic_blocks = list(flowchart)
    print(f'Total basic blocks: {len(basic_blocks)}')

    # Show first 15 basic blocks to avoid overwhelming output
    display_count = min(15, len(basic_blocks))
    if display_count < len(basic_blocks):
        print(f'Displaying first {display_count} basic blocks:')

    for i, bb in enumerate(basic_blocks[:display_count], 1):
        print(f'  [{i:2d}] Start: 0x{bb.start_ea:08x} | End: 0x{bb.end_ea:08x}')

    if display_count < len(basic_blocks):
        print(f'  ... and {len(basic_blocks) - display_count} more basic blocks')


def traverse_instructions(db: ida_domain.Database) -> None:
    """
    Traverse and display instructions with disassembly.

    Args:
        db: The IDA database instance
    """
    print_section_header('INSTRUCTIONS')

    instructions = list(db.instructions)
    print(f'Total instructions: {len(instructions)}')

    # Show first 20 instructions to avoid overwhelming output
    display_count = min(20, len(instructions))
    if display_count < len(instructions):
        print(f'Displaying first {display_count} instructions:')

    for i, inst in enumerate(instructions[:display_count], 1):
        disasm = db.instructions.get_disassembly(inst)
        if disasm:
            print(f'  [{i:2d}] 0x{inst.ea:08x}: {disasm}')
        else:
            print(f'  [{i:2d}] 0x{inst.ea:08x}: <no disassembly>')

    if display_count < len(instructions):
        print(f'  ... and {len(instructions) - display_count} more instructions')


def traverse_cross_references(db: ida_domain.Database) -> None:
    """
    Traverse and display cross-references.

    Args:
        db: The IDA database instance
    """
    print_section_header('CROSS-REFERENCES')

    # Get a sample of addresses to check for cross-references
    sample_addresses = []

    # Add function start addresses
    functions = list(db.functions)
    sample_addresses.extend([f.start_ea for f in functions[:5]])

    # Add some heads
    heads = list(db.heads)
    sample_addresses.extend(heads[:5])

    xref_count = 0
    print('Sample cross-references:')

    for addr in sample_addresses[:10]:  # Limit to first 10 addresses
        xrefs_to = list(db.xrefs.to_ea(addr))
        xrefs_from = list(db.xrefs.from_ea(addr))

        if xrefs_to or xrefs_from:
            print(f'  Address 0x{addr:08x}:')

            for xref in xrefs_to[:3]:  # Show max 3 xrefs to
                type_name = xref.type.name
                print(f'    <- FROM 0x{xref.from_ea:08x} (type: {type_name})')
                xref_count += 1

            for xref in xrefs_from[:3]:  # Show max 3 xrefs from
                type_name = xref.type.name
                print(f'    -> TO   0x{xref.to_ea:08x} (type: {type_name})')
                xref_count += 1

    print(f'Total cross-references displayed: {xref_count}')


def traverse_database(db_path: str):
    """
    Main function to traverse the entire IDA database and display all entities.

    Args:
        db_path: Path to the binary file to analyze
    """
    print_section_header('IDA DOMAIN DATABASE TRAVERSAL', '=')
    print(f'Analyzing file: {db_path}')

    # Configure IDA options for analysis
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)

    # Open database
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Traverse all database entities
        traverse_metadata(db)
        traverse_segments(db)
        traverse_functions(db)
        traverse_entries(db)
        traverse_heads(db)
        traverse_strings(db)
        traverse_names(db)
        traverse_types(db)
        traverse_comments(db)
        traverse_basic_blocks(db)
        traverse_instructions(db)
        traverse_cross_references(db)

        print_section_header('TRAVERSAL COMPLETE', '=')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='IDA Database Traversal Example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    traverse_database(args.input_file)


if __name__ == '__main__':
    main()

```

## Function Analysis

### Finding and Analyzing Functions

```
#!/usr/bin/env python3
"""
Function analysis example for IDA Domain API.

This example demonstrates how to find and analyze functions in an IDA database.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze_local_variables(db: Database, func: 'func_t') -> None:
    """Analyze local variables in a function."""
    lvars = db.functions.get_local_variables(func)
    if not lvars:
        print('  No local variables found')
        return

    print(f'  Local variables ({len(lvars)} total):')

    for lvar in lvars:
        refs = db.functions.get_local_variable_references(func, lvar)
        ref_count = len(refs)
        var_type = 'arg' if lvar.is_argument else 'ret' if lvar.is_result else 'var'
        type_str = lvar.type_str if lvar.type else 'unknown'

        print(f'    {lvar.name} ({var_type}, {type_str}): {ref_count} refs')

        # Show first reference with line info if available
        if refs and refs[0].line_number is not None:
            first_ref = refs[0]
            print(f'      first ref at line {first_ref.line_number}: {first_ref.code_line}')


def analyze_functions(
    db_path: str, pattern: str = 'main', max_results: int = 10, analyze_lvars: bool = True
) -> None:
    """Find and analyze functions matching a pattern."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Find functions matching a pattern
        matching_functions = []
        for func in db.functions:
            func_name = db.functions.get_name(func)
            if pattern.lower() in func_name.lower():
                matching_functions.append((func, func_name))

        print(f"Found {len(matching_functions)} functions matching '{pattern}':")

        # Limit results if requested
        display_functions = (
            matching_functions[:max_results] if max_results > 0 else matching_functions
        )

        for func, name in display_functions:
            print(f'\nFunction: {name}')
            print(f'\nAddress: {hex(func.start_ea)} - {hex(func.end_ea)}')

            # Get signature
            signature = db.functions.get_signature(func)
            print(f'\nSignature: {signature}')

            # Get basic blocks
            flowchart = db.functions.get_flowchart(func)
            print(f'\nBasic blocks count: {len(flowchart)}')

            # Analyze local variables if requested
            if analyze_lvars:
                print('\nLocal variable analysis:')
                analyze_local_variables(db, func)

            # Show first few lines of disassembly
            disasm = db.functions.get_disassembly(func)
            print('\nDisassembly:')
            for line in disasm:
                print(f'  {line}')

            # Show first few lines of pseudocode
            pseudocode = db.functions.get_pseudocode(func)
            print('\nPseudocode :')
            for line in pseudocode:
                print(f'  {line}')

        if max_results > 0 and len(matching_functions) > max_results:
            print(f'\n... (showing first {max_results} of {len(matching_functions)} matches)')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Function analysis examples')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-p',
        '--pattern',
        default='main',
        help='Pattern to search for in function names (default: main)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=10,
        help='Maximum number of results to display (0 for all, default: 10)',
    )
    parser.add_argument(
        '-l',
        '--analyze-locals',
        action='store_true',
        help='Analyze local variables in functions',
    )
    args = parser.parse_args()
    analyze_functions(args.input_file, args.pattern, args.max_results, args.analyze_locals)


if __name__ == '__main__':
    main()

```

## Signature Files

### Working with FLIRT signature files

```
#!/usr/bin/env python3
"""
Using FLIRT signature files example in IDA Domain API.

This example demonstrates how to work with signature files:
  - how to evaluate the matches on your binary
  - how to actually apply a sig file
  - how to generate .sig/.pat from your loaded binary
  - how to use custom signature directories
"""

import argparse
from pathlib import Path

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_domain.signature_files import FileInfo


def probe_signature_files(db: ida_domain.Database, min_matches: int, custom_dir: str = None):
    """Probe signature files and collect the ones over the minimum number of matches."""
    print('Probing signature files...')
    directories = [Path(custom_dir)] if custom_dir else None
    files = db.signature_files.get_files(directories=directories)

    good_matches = []
    for sig_file in files:
        results = db.signature_files.apply(sig_file, probe_only=True)
        for result in results:
            if result.matches >= min_matches:
                good_matches.append(result)
                print(f'{sig_file.name}: {result.matches} matches')

    return good_matches


def apply_signature_files(db: ida_domain.Database, matches: list[FileInfo], min_matches: int):
    """Apply signature files over the minimum number of matches."""
    if not matches:
        return

    print('\nApplying signature files...')
    for result in matches:
        if result.matches >= min_matches:
            sig_path = Path(result.path)
            print(f'Applying {sig_path.name}')
            db.signature_files.apply(sig_path, probe_only=False)


def generate_signatures(db: ida_domain.Database):
    """Generate signature files from current database."""
    print('\nGenerating signatures...')
    produced_files = db.signature_files.create()
    if produced_files:
        for file_path in produced_files:
            print(f'Generated: {Path(file_path).name}')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='FLIRT signature files example')
    parser.add_argument('-f', '--input-file', required=True, help='Binary file to analyze')
    parser.add_argument('-d', '--sig-dir', help='Directory where to look for signature files')
    parser.add_argument('-p', '--min-probe-matches', default=5, type=int)
    parser.add_argument('-a', '--min-apply-matches', default=10, type=int)
    args = parser.parse_args()

    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(args.input_file, ida_options) as db:
        matches = probe_signature_files(db, args.min_probe_matches, args.sig_dir)
        apply_signature_files(db, matches, args.min_apply_matches)
        generate_signatures(db)


if __name__ == '__main__':
    main()

```

## String Analysis

### Finding and Analyzing Strings

```
#!/usr/bin/env python3
"""
String analysis example for IDA Domain API.

This example demonstrates how to find and analyze strings in an IDA database.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze_strings(db_path, min_length=5, max_display=20, show_interesting=True):
    """Find and analyze strings in the database."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(db_path, ida_options) as db:
        print(f'Analyzing strings (minimum length: {min_length}):')

        # Collect all strings
        all_strings = []
        interesting_strings = []

        for item in db.strings:
            if item.length >= min_length:
                all_strings.append((item.address, str(item)))

                # Check for interesting keywords
                if show_interesting:
                    lower_str = str(item).lower()
                    interesting_keywords = [
                        'password',
                        'passwd',
                        'pwd',
                        'key',
                        'secret',
                        'token',
                        'api',
                        'username',
                        'user',
                        'login',
                        'config',
                        'settings',
                        'registry',
                        'file',
                        'path',
                        'directory',
                        'http',
                        'https',
                        'ftp',
                        'url',
                        'sql',
                        'database',
                        'query',
                    ]

                    if any(keyword in lower_str for keyword in interesting_keywords):
                        interesting_strings.append((item.address, str(item)))

        print(f'Total strings: {len(db.strings)}')
        print(f'Strings >= {min_length} chars: {len(all_strings)}')

        # Display regular strings
        print(f'\nFirst {max_display} strings:')
        for i, (addr, string_value) in enumerate(all_strings[:max_display]):
            print(f'{hex(addr)}: {repr(string_value)}')

        if len(all_strings) > max_display:
            print(f'... (showing first {max_display} of {len(all_strings)} strings)')

        # Display interesting strings
        if show_interesting and interesting_strings:
            print(f'\nInteresting strings found ({len(interesting_strings)}):')
            for addr, string_value in interesting_strings[:10]:  # Limit to 10
                print(f'{hex(addr)}: {repr(string_value)}')

            if len(interesting_strings) > 10:
                print(f'... (showing first 10 of {len(interesting_strings)} interesting strings)')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-l', '--min-length', type=int, default=5, help='Minimum string length(default: 5)'
    )
    parser.add_argument(
        '-m', '--max-display', type=int, default=20, help='Maximum displayed strings (default: 20)'
    )
    parser.add_argument(
        '-s',
        '--show-interesting',
        type=bool,
        default=True,
        help='Highlight interesting strings (default True)',
    )
    args = parser.parse_args()
    analyze_strings(args.input_file, args.min_length, args.max_display, args.show_interesting)


if __name__ == '__main__':
    main()

```

## Bytes Analysis

### Analyzing and Manipulating Bytes

```
#!/usr/bin/env python3
"""
Byte analysis example for IDA Domain API.

This example demonstrates how to analyze, search, and manipulate bytes in an IDA database.
It showcases the comprehensive byte manipulation capabilities including data type operations,
patching, flag checking, and search functionality.
"""

import argparse
from typing import Optional

import ida_domain
from ida_domain import Database
from ida_domain.bytes import ByteFlags, SearchFlags, StringType
from ida_domain.database import IdaCommandOptions


def analyze_bytes(
    db_path: str,
    search_pattern: Optional[str] = None,
    patch_demo: bool = False,
    max_results: int = 20,
) -> None:
    """Analyze and manipulate bytes in the database."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(path=db_path, args=ida_options, save_on_close=False) as db:
        bytes_handler = db.bytes

        print('=== IDA Domain Bytes Analysis ===\n')

        # 1. Basic byte reading operations
        print('1. Basic Byte Reading Operations:')
        print('-' * 40)

        # Read different data types from entry point
        entry_point = db.minimum_ea
        print(f'Entry point: {hex(entry_point)}')

        byte_val = bytes_handler.get_byte_at(entry_point)
        word_val = bytes_handler.get_word_at(entry_point)
        dword_val = bytes_handler.get_dword_at(entry_point)
        qword_val = bytes_handler.get_qword_at(entry_point)

        print(f'  Byte:  0x{byte_val:02x} ({byte_val})')
        print(f'  Word:  0x{word_val:04x} ({word_val})')
        print(f'  DWord: 0x{dword_val:08x} ({dword_val})')
        print(f'  QWord: 0x{qword_val:016x} ({qword_val})')

        # Get disassembly
        disasm = bytes_handler.get_disassembly_at(entry_point)
        print(f'  Disassembly: {disasm}')

        # 2. Data type analysis using flags
        print('\n2. Data Type Analysis:')
        print('-' * 40)

        # Analyze different addresses
        test_addresses = [entry_point, entry_point + 0x10, entry_point + 0x20]
        for addr in test_addresses:
            if not db.is_valid_ea(addr):
                continue

            flags = bytes_handler.get_flags_at(addr)
            data_size = bytes_handler.get_data_size_at(addr)

            # Use new flag checking methods
            is_code = bytes_handler.check_flags_at(addr, ByteFlags.CODE)
            is_data = bytes_handler.check_flags_at(addr, ByteFlags.DATA)
            has_any_data_flags = bytes_handler.has_any_flags_at(
                addr, ByteFlags.BYTE | ByteFlags.WORD | ByteFlags.DWORD
            )

            print(f'  Address {hex(addr)}:')
            print(f'    Flags: 0x{flags:x}')
            print(f'    Is Code: {is_code}, Is Data: {is_data}')
            print(f'    Has Data Flags: {has_any_data_flags}')
            print(f'    DataSize: {data_size}')

        # 3. Search operations
        print('\n3. Search Operations:')
        print('-' * 40)

        # Search for common patterns
        patterns_to_search = [
            (b'\x48\x89\xe5', 'Function prologue (mov rbp, rsp)'),
            (b'\x55', 'Push rbp'),
            (b'\xc3', 'Return instruction'),
        ]

        for pattern, description in patterns_to_search:
            found_addr = bytes_handler.find_bytes_between(pattern)
            if found_addr:
                print(f'  Found {description} at {hex(found_addr)}')
            else:
                print(f'  {description} not found')

        # Text search with flags
        if search_pattern:
            print(f"\n  Searching for text: '{search_pattern}'")
            # Case-sensitive search
            addr_case = bytes_handler.find_text(
                search_pattern, flags=SearchFlags.DOWN | SearchFlags.CASE
            )
            # Case-insensitive search
            addr_nocase = bytes_handler.find_text_between(search_pattern, flags=SearchFlags.DOWN)

            if addr_case:
                print(f'    Case-sensitive found at: {hex(addr_case)}')
            if addr_nocase and addr_nocase != addr_case:
                print(f'    Case-insensitive found at: {hex(addr_nocase)}')
            if not addr_case and not addr_nocase:
                print(f"    Text '{search_pattern}' not found")

        # Search for immediate values
        immediate_addr = bytes_handler.find_immediate_between(1)
        if immediate_addr is not None:
            print(f'  Found immediate value 1 at {hex(immediate_addr)}')

        # 4. String operations
        print('\n4. String Operations:')
        print('-' * 40)

        # Find and analyze strings
        string_count = 0
        for item in db.strings:
            if string_count >= 3:  # Limit output
                break

            print(f'  String at {hex(item.address)}: {str(item)}')

            # Try different string reading methods
            cstring = bytes_handler.get_cstring_at(item.address)
            if cstring:
                print(f'    C-string: {repr(cstring)}')

            string_count += 1

        # 5. Data type creation
        print('\n5. Data Type Creation:')
        print('-' * 40)

        # Find a suitable data address for demonstration
        data_addr = None
        for addr in range(db.minimum_ea, min(db.minimum_ea + 0x100, db.maximum_ea), 4):
            if bytes_handler.is_data_at(addr) or bytes_handler.is_unknown_at(addr):
                data_addr = addr
                break

        if data_addr:
            print(f'  Working with data at {hex(data_addr)}')

            # Create different data types
            original_flags = bytes_handler.get_flags_at(data_addr)
            print(f'    Original flags: {original_flags}')

            # Make it a byte
            if bytes_handler.make_byte_at(data_addr):
                print(f'    Successfully created byte at {hex(data_addr)}')

            # Make it a word
            if bytes_handler.make_word(data_addr):
                print(f'    Successfully created word at {hex(data_addr)}')

            # Create a string with specific type
            string_addr = data_addr + 8
            if bytes_handler.make_string(string_addr, string_type=StringType.C):
                print(f'    Successfully created C-string at {hex(string_addr)}')

        # 6. Patching demonstration (if requested)
        if patch_demo:
            print('\n6. Patching Demonstration:')
            print('-' * 40)

            # Find a safe address to patch (data section)
            patch_addr = None
            for addr in range(db.minimum_ea, min(db.minimum_ea + 0x200, db.maximum_ea)):
                if bytes_handler.is_data(addr):
                    patch_addr = addr
                    break

            if patch_addr:
                print(f'  Demonstrating patching at {hex(patch_addr)}')

                # Get original values
                orig_byte = bytes_handler.get_byte_at(patch_addr)
                orig_word = bytes_handler.get_word_at(patch_addr)

                print(f'    Original byte: 0x{orig_byte:02x}')
                print(f'    Original word: 0x{orig_word:04x}')

                # Patch byte
                if bytes_handler.patch_byte_at(patch_addr, 0xAB):
                    new_byte = bytes_handler.get_byte_at(patch_addr)
                    print(f'    Patched byte: 0x{new_byte:02x}')

                    # Get original value
                    retrieved_orig = bytes_handler.get_original_byte_at(patch_addr)
                    print(f'    Retrieved original: 0x{retrieved_orig:02x}')

                    # Revert patch
                    if bytes_handler.revert_byte_at(patch_addr):
                        reverted_byte = bytes_handler.get_byte_at(patch_addr)
                        print(f'    Reverted byte: 0x{reverted_byte:02x}')

                # Patch multiple bytes
                test_data = b'\x90\x90\x90\x90'  # NOP instructions
                if bytes_handler.patch_bytes(patch_addr, test_data):
                    print(f'    Patched {len(test_data)} bytes with NOPs')

                    # Get original bytes
                    success, orig_bytes = bytes_handler.get_original_bytes_at(
                        patch_addr, len(test_data)
                    )
                    if success:
                        print(f'    Original bytes: {orig_bytes.hex()}')

        # 7. Navigation helpers
        print('\n7. Navigation Helpers:')
        print('-' * 40)

        test_addr = entry_point + 0x10
        if test_addr <= db.maximum_ea:
            next_head = bytes_handler.get_next_head(test_addr)
            prev_head = bytes_handler.get_previous_head(test_addr)
            next_addr = bytes_handler.get_next_address(test_addr)
            prev_addr = bytes_handler.get_previous_address(test_addr)

            print(f'  From address {hex(test_addr)}:')
            print(
                f'    Next head: {hex(next_head) if next_head != 0xFFFFFFFFFFFFFFFF else "None"}'
            )
            print(
                f'    Prev head: {hex(prev_head) if prev_head != 0xFFFFFFFFFFFFFFFF else "None"}'
            )
            print(f'    Next addr: {hex(next_addr)}')
            print(f'    Prev addr: {hex(prev_addr)}')

        # 8. Summary statistics
        print('\n8. Summary Statistics:')
        print('-' * 40)

        code_count = data_count = unknown_count = 0
        sample_size = db.maximum_ea - db.minimum_ea

        for addr in range(db.minimum_ea, db.minimum_ea + sample_size):
            if not db.is_valid_ea(addr):
                continue
            if bytes_handler.is_code_at(addr):
                code_count += 1
            elif bytes_handler.is_data_at(addr):
                data_count += 1
            elif bytes_handler.is_unknown_at(addr):
                unknown_count += 1

        print(f'  Sample size: {sample_size} bytes')
        print(f'  Code bytes: {code_count} ({code_count / sample_size * 100:.1f}%)')
        print(f'  Data bytes: {data_count} ({data_count / sample_size * 100:.1f}%)')
        print(f'  Unknown bytes: {unknown_count} ({unknown_count / sample_size * 100:.1f}%)')

        print('\n=== Analysis Complete ===')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Byte analysis example for IDA Domain API')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-s',
        '--search-pattern',
        help='Text pattern to search for in the binary',
        type=str,
        default=None,
    )
    parser.add_argument(
        '-p',
        '--patch-demo',
        action='store_true',
        help='Demonstrate patching operations (modifies database temporarily)',
    )
    parser.add_argument(
        '-m',
        '--max-results',
        type=int,
        default=20,
        help='Maximum number of results to display (default: 20)',
    )

    args = parser.parse_args()
    analyze_bytes(args.input_file, args.search_pattern, args.patch_demo, args.max_results)


if __name__ == '__main__':
    main()

```

## Type Analysis

### Analyzing and Working with Types

```
#!/usr/bin/env python3
"""
Types example for IDA Domain API.

This example demonstrates how to work with IDA's type information libraries.
"""

import argparse
import tempfile
from pathlib import Path

import ida_domain
from ida_domain import Database


def print_section_header(title: str, char: str = '=') -> None:
    """Print a formatted section header for better output organization."""
    print(f'\n{char * 60}')
    print(f' {title}')
    print(f'{char * 60}')


def print_subsection_header(title: str) -> None:
    """Print a formatted subsection header."""
    print(f'\n--- {title} ---')


declarations = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

struct STRUCT_EXAMPLE
{
    char *text;
    unsigned int length;
    uint32_t reserved;
};

"""


def create_types(db: Database, library_path: Path):
    """Create a type library and fill it with types parsed from declaration"""

    til = db.types.create_library(library_path, 'Example type information library')
    db.types.parse_declarations(til, declarations)
    db.types.save_library(til, library_path)
    db.types.unload_library(til)


def import_types(db: Database, library_path: Path):
    """Import all types from external library"""

    til = db.types.load_library(library_path)

    print_subsection_header(f'Type names from external library {library_path}')
    for name in db.types.get_all(library=til):
        print(name)

    print_subsection_header('Type information objects in local library (before import)')
    for item in sorted(list(db.types), key=lambda i: i.get_ordinal()):
        print(f'{item.get_ordinal()}. {item}')

    db.types.import_from_library(til)

    print_subsection_header('Type information objects in local library (after import)')
    for item in sorted(list(db.types), key=lambda i: i.get_ordinal()):
        print(f'{item.get_ordinal()}. {item}')

    db.types.unload_library(til)


def export_types(db: Database, library_path: Path):
    """Export all types from database to external library"""

    til = db.types.create_library(library_path, 'Exported type library')
    db.types.export_to_library(til)
    db.types.save_library(til, library_path)
    db.types.unload_library(til)

    print_subsection_header(f'Types exported to {library_path}')
    til = db.types.load_library(library_path)
    for t in db.types.get_all(library=til):
        print(t)
    db.types.unload_library(til)


def main():
    parser = argparse.ArgumentParser(
        description=f'IDA Domain usage example, version {ida_domain.__version__}'
    )
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()

    library_dir = Path(tempfile.gettempdir()) / 'ida_domain_example'
    library_dir.mkdir(parents=True, exist_ok=True)
    library_create_path = library_dir / 'new.til'
    library_import_path = library_dir / 'new.til'
    library_export_path = library_dir / 'exported.til'

    print_section_header('Working with type information libraries')

    with Database.open(args.input_file) as db:
        create_types(db, library_create_path)
        import_types(db, library_import_path)
        export_types(db, library_export_path)


if __name__ == '__main__':
    main()

```

## Cross-Reference Analysis

### Analyzing Cross-References

```
#!/usr/bin/env python3
"""
Cross-reference analysis example for IDA Domain API.

This example demonstrates how to analyze cross-references in an IDA database.
"""

import argparse

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions


def analyze_xrefs(db_path, target_addr):
    """Analyze cross-references to and from a target address."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(db_path, ida_options) as db:
        print(f'Cross-references to {hex(target_addr)}:')

        # Get references TO the target address
        xref_to_count = 0
        for xref in db.xrefs.to_ea(target_addr):
            xref_type_name = xref.type.name
            print(f'  From {hex(xref.from_ea)} to {hex(xref.to_ea)} (type: {xref_type_name})')
            xref_to_count += 1

        if xref_to_count == 0:
            print('  No cross-references found')
        else:
            print(f'  Total: {xref_to_count} references')

        print(f'\nCross-references from {hex(target_addr)}:')

        # Get references FROM the target address
        xref_from_count = 0
        for xref in db.xrefs.from_ea(target_addr):
            xref_type_name = xref.type.name
            print(f'  From {hex(xref.from_ea)} to {hex(xref.to_ea)} (type: {xref_type_name})')
            xref_from_count += 1

        if xref_from_count == 0:
            print('  No outgoing references found')
        else:
            print(f'  Total: {xref_from_count} outgoing references')

        # Use convenience methods for specific xref types
        call_count = sum(1 for _ in db.xrefs.calls_to_ea(target_addr))
        jump_count = sum(1 for _ in db.xrefs.jumps_to_ea(target_addr))
        read_count = sum(1 for _ in db.xrefs.reads_of_ea(target_addr))
        write_count = sum(1 for _ in db.xrefs.writes_to_ea(target_addr))

        # Summary
        print(f'\nSummary for {hex(target_addr)}:')
        print(f'  Calls to address: {call_count}')
        print(f'  Jumps to address: {jump_count}')
        print(f'  Data reads to address: {read_count}')
        print(f'  Data writes to address: {write_count}')
        print(f'  Incoming references: {xref_to_count}')
        print(f'  Outgoing references: {xref_from_count}')


def parse_address(value):
    """Parse address as either decimal or hexadecimal"""
    try:
        if value.lower().startswith('0x'):
            return int(value, 16)
        else:
            return int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f'Invalid address format: {value}')


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    parser.add_argument(
        '-a',
        '--address',
        help='Address (decimal or hex with 0x prefix)',
        type=parse_address,
        required=True,
    )
    args = parser.parse_args()
    analyze_xrefs(args.input_file, args.address)


if __name__ == '__main__':
    main()

```

## Event Handling (Hooks)

### Hooking and Logging Events

```
#!/usr/bin/env python3
"""
Event handling / hook usage example for IDA Domain API.

This example demonstrates how to handle IDA events.
"""

import argparse
import logging

from ida_domain import database, hooks  # isort: skip
import ida_idaapi  # isort: skip

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')


# Processor hooks example
class MyProcHooks(hooks.ProcessorHooks):
    def __init__(self):
        super().__init__()

    def ev_creating_segm(self, seg: 'segment_t *') -> int:
        self.log()
        return super().ev_creating_segm(seg)

    def ev_moving_segm(self, seg: 'segment_t *', to: ida_idaapi.ea_t, flags: int) -> int:
        self.log()
        return super().ev_moving_segm(seg, to, flags)


# UI hooks example
class MyUIHooks(hooks.UIHooks):
    def __init__(self):
        super().__init__()

    def widget_visible(self, widget: 'TWidget *') -> None:
        self.log()

    def widget_closing(self, widget: 'TWidget *') -> None:
        self.log()

    def widget_invisible(self, widget: 'TWidget *') -> None:
        self.log()


# View hooks example
class MyViewHooks(hooks.ViewHooks):
    def __init__(self):
        super().__init__()

    def view_activated(self, view: 'TWidget *') -> None:
        self.log()

    def view_deactivated(self, view: 'TWidget *') -> None:
        self.log()


# Decompiler hooks example
class MyDecompilerHooks(hooks.DecompilerHooks):
    def __init__(self):
        super().__init__()

    def open_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().open_pseudocode()

    def switch_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().switch_pseudocode()

    def refresh_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().refresh_pseudocode()

    def close_pseudocode(self, vu: 'vdui_t') -> int:
        self.log()
        return super().close_pseudocode()


# Database hooks example
class MyDatabaseHooks(hooks.DatabaseHooks):
    def __init__(self):
        super().__init__()
        self.count = 0

    def closebase(self) -> None:
        self.log()

    def auto_empty(self):
        self.log()

    def segm_added(self, s) -> None:
        self.log()


proc_hook = MyProcHooks()
ui_hook = MyUIHooks()
view_hook = MyViewHooks()
decomp_hook = MyDecompilerHooks()
db_hook = MyDatabaseHooks()

all_hooks: hooks.HooksList = [
    proc_hook,
    ui_hook,
    view_hook,
    decomp_hook,
    db_hook,
]


def log_events(idb_path):
    with database.Database.open(path=idb_path, hooks=all_hooks) as db:
        pass


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    log_events(args.input_file)


if __name__ == '__main__':
    main()

```

## Running the Examples

To run these examples, save them to Python files and execute them with your IDA database path:

```
python example_script.py

```

Make sure you have:

1. Set the `IDADIR` environment variable
1. Installed the ida-domain package

# Getting Started

This guide will take you from nothing to a working first script with the IDA Domain API.

## Prerequisites

- **Python 3.9 or higher**
- **IDA Pro 9.1 or higher**

## Installation

### Step 1: Set up IDA SDK Access

The IDA Domain API needs access to the IDA SDK. Choose one of these options:

**Option A: Set IDADIR Environment Variable**

Point to your IDA installation directory:

```
export IDADIR="/Applications/IDA Professional 9.2.app/Contents/MacOS/"

```

```
export IDADIR="/opt/ida-9.2/"

```

```
set IDADIR="C:\Program Files\IDA Professional 9.2\"

```

To make this permanent, add the export command to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.).

**Option B: Use idapro Python Package**

If you already have the `idapro` Python package configured, skip setting `IDADIR`.

### Step 2: Install the Package

For a clean environment, use a virtual environment:

```
# Create and activate virtual environment
python -m venv ida-env
source ida-env/bin/activate  # On Windows: ida-env\Scripts\activate

# Install the package
pip install ida-domain

```

### Step 3: Verify Installation

```
# test_install.py
try:
    from ida_domain import Database
    print("✓ Installation successful!")
except ImportError as e:
    print(f"✗ Installation failed: {e}")

```

## Your First Script

Create a simple script to explore an IDA database:

```
# my_first_script.py
import argparse

from ida_domain import Database


def explore_database(db_path):
    # Create and open database
    with Database.open(path=db_path, save_on_close=False) as db:
        # Basic database info
        print(f'✓ Opened: {db_path}')
        print(f'  Architecture: {db.architecture}')
        print(f'  Entry point: {hex(db.entries[0].address)}')
        print(f'  Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

        # Count functions
        func_count = len(list(db.functions))
        print(f'  Functions: {func_count}')

        # Count strings
        string_count = len(list(db.strings))
        print(f'  Strings: {string_count}')
    print('✓ Database closed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input-file', type=str, required=True)
    args = parser.parse_args()
    # Run with your IDA input file
    explore_database(args.input_file)

```

**To run this script:**

Run: `python my_first_script.py -f <binary input file>`

**Expected output:**

```
✓ Opened: /path/to/sample.idb
  Architecture: x86_64
  Entry point: 0x1000
  Address range: 0x1000 - 0x2000
  Functions: 42
  Strings: 15
✓ Database closed

```

## Running Scripts Inside IDA

The examples above show **library mode** - running standalone Python scripts outside IDA. You can also use IDA Domain from **inside the IDA GUI** for interactive analysis.

When running inside IDA, call `Database.open()` with no arguments to get a handle to the currently open database:

```
# ida_console_example.py
# Run this from IDA's IDAPython console or via File → Script command
from ida_domain import Database

# Get handle to currently open database (no path needed)
with Database.open() as db:
    print(f"Current database: {db.path}")
    print(f"Architecture: {db.architecture}")
    print(f"Functions: {len(list(db.functions))}")

```

**Key difference from library mode:**

- No file path argument - database is already open

## Troubleshooting

**ImportError: No module named 'ida_domain'**

- Run `pip install ida-domain`
- Check you're in the correct virtual environment

**IDA SDK not found**

- Verify `IDADIR` is set: `echo $IDADIR`
- Ensure the path points to your actual IDA installation

**Database won't open**

- Check the file path exists
- Ensure the database was created with IDA Pro 9.0+

## Next Steps

1. **[Examples](../examples/)** - Complete examples for real-world tasks
1. **[API Reference](../usage/)** - Detailed API documentation
1. **Start your project** - Apply these concepts to your reverse engineering work!
# API Reference

# `Bytes`

## bytes

Classes:

- **`ByteFlags`** – Byte flag constants for flag checking operations.
- **`Bytes`** – Handles operations related to raw data access from the IDA database.
- **`NoValueError`** – Raised when a read operation is attempted on an uninitialized address.
- **`SearchFlags`** – Search flags for text and pattern searching.
- **`UnsupportedValueError`** – Raised when a read operation is attempted on a value which has an unsupported format.

### ByteFlags

Bases: `IntFlag`

Byte flag constants for flag checking operations.

Attributes:

- **`ALIGN`** – Alignment directive
- **`ANYNAME`** – Has name or dummy name?
- **`BNOT`** – Bitwise negation of operands
- **`BYTE`** – Byte
- **`CODE`** – Code?
- **`COMM`** – Has comment?
- **`CUSTOM`** – Custom data type
- **`DATA`** – Data?
- **`DOUBLE`** – Double
- **`DWORD`** – Double word
- **`FLOAT`** – Float
- **`FLOW`** – Exec flow from prev instruction
- **`FUNC`** – Function start?
- **`IMMD`** – Has immediate value?
- **`IVL`** – Byte has value.
- **`JUMP`** – Has jump table or switch_info?
- **`LABL`** – Has dummy name?
- **`LINE`** – Has next or prev lines?
- **`MS_VAL`** – Mask for byte value.
- **`NAME`** – Has name?
- **`N_CHAR`** – Char ('x')?
- **`N_CUST`** – Custom representation?
- **`N_ENUM`** – Enumeration?
- **`N_FLT`** – Floating point number?
- **`N_FOP`** – Forced operand?
- **`N_NUMB`** – Binary number?
- **`N_NUMD`** – Decimal number?
- **`N_NUMH`** – Hexadecimal number?
- **`N_NUMO`** – Octal number?
- **`N_OFF`** – Offset?
- **`N_SEG`** – Segment?
- **`N_STK`** – Stack variable?
- **`N_STRO`** – Struct offset?
- **`N_VOID`** – Void (unknown)?
- **`OWORD`** – Octaword/XMM word (16 bytes)
- **`PACKREAL`** – Packed decimal real
- **`QWORD`** – Quad word
- **`REF`** – Has references
- **`SIGN`** – Inverted sign of operands
- **`STRLIT`** – String literal
- **`STRUCT`** – Struct variable
- **`TAIL`** – Tail?
- **`TBYTE`** – TByte
- **`UNK`** – Unknown?
- **`UNUSED`** – Unused bit
- **`WORD`** – Word
- **`YWORD`** – YMM word (32 bytes)
- **`ZWORD`** – ZMM word (64 bytes)

#### ALIGN

```
ALIGN = FF_ALIGN

```

Alignment directive

#### ANYNAME

```
ANYNAME = FF_ANYNAME

```

Has name or dummy name?

#### BNOT

```
BNOT = FF_BNOT

```

Bitwise negation of operands

#### BYTE

```
BYTE = FF_BYTE

```

Byte

#### CODE

```
CODE = FF_CODE

```

Code?

#### COMM

```
COMM = FF_COMM

```

Has comment?

#### CUSTOM

```
CUSTOM = FF_CUSTOM

```

Custom data type

#### DATA

```
DATA = FF_DATA

```

Data?

#### DOUBLE

```
DOUBLE = FF_DOUBLE

```

Double

#### DWORD

```
DWORD = FF_DWORD

```

Double word

#### FLOAT

```
FLOAT = FF_FLOAT

```

Float

#### FLOW

```
FLOW = FF_FLOW

```

Exec flow from prev instruction

#### FUNC

```
FUNC = FF_FUNC

```

Function start?

#### IMMD

```
IMMD = FF_IMMD

```

Has immediate value?

#### IVL

```
IVL = FF_IVL

```

Byte has value.

#### JUMP

```
JUMP = FF_JUMP

```

Has jump table or switch_info?

#### LABL

```
LABL = FF_LABL

```

Has dummy name?

#### LINE

```
LINE = FF_LINE

```

Has next or prev lines?

#### MS_VAL

```
MS_VAL = MS_VAL

```

Mask for byte value.

#### NAME

```
NAME = FF_NAME

```

Has name?

#### N_CHAR

```
N_CHAR = FF_N_CHAR

```

Char ('x')?

#### N_CUST

```
N_CUST = FF_N_CUST

```

Custom representation?

#### N_ENUM

```
N_ENUM = FF_N_ENUM

```

Enumeration?

#### N_FLT

```
N_FLT = FF_N_FLT

```

Floating point number?

#### N_FOP

```
N_FOP = FF_N_FOP

```

Forced operand?

#### N_NUMB

```
N_NUMB = FF_N_NUMB

```

Binary number?

#### N_NUMD

```
N_NUMD = FF_N_NUMD

```

Decimal number?

#### N_NUMH

```
N_NUMH = FF_N_NUMH

```

Hexadecimal number?

#### N_NUMO

```
N_NUMO = FF_N_NUMO

```

Octal number?

#### N_OFF

```
N_OFF = FF_N_OFF

```

Offset?

#### N_SEG

```
N_SEG = FF_N_SEG

```

Segment?

#### N_STK

```
N_STK = FF_N_STK

```

Stack variable?

#### N_STRO

```
N_STRO = FF_N_STRO

```

Struct offset?

#### N_VOID

```
N_VOID = FF_N_VOID

```

Void (unknown)?

#### OWORD

```
OWORD = FF_OWORD

```

Octaword/XMM word (16 bytes)

#### PACKREAL

```
PACKREAL = FF_PACKREAL

```

Packed decimal real

#### QWORD

```
QWORD = FF_QWORD

```

Quad word

#### REF

```
REF = FF_REF

```

Has references

#### SIGN

```
SIGN = FF_SIGN

```

Inverted sign of operands

#### STRLIT

```
STRLIT = FF_STRLIT

```

String literal

#### STRUCT

```
STRUCT = FF_STRUCT

```

Struct variable

#### TAIL

```
TAIL = FF_TAIL

```

Tail?

#### TBYTE

```
TBYTE = FF_TBYTE

```

TByte

#### UNK

```
UNK = FF_UNK

```

Unknown?

#### UNUSED

```
UNUSED = FF_UNUSED

```

Unused bit

#### WORD

```
WORD = FF_WORD

```

Word

#### YWORD

```
YWORD = FF_YWORD

```

YMM word (32 bytes)

#### ZWORD

```
ZWORD = FF_ZWORD

```

ZMM word (64 bytes)

### Bytes

```
Bytes(database: Database)

```

Bases: `DatabaseEntity`

Handles operations related to raw data access from the IDA database.

This class provides methods to read various data types (bytes, words, floats, etc.) from memory addresses in the disassembled binary.

Args: database: Reference to the active IDA database.

Methods:

- **`check_flags_at`** – Checks if the specified flags are set at the given address.
- **`create_alignment_at`** – Create an alignment item.
- **`create_byte_at`** – Creates byte data items at consecutive addresses starting from the specified address.
- **`create_double_at`** – Creates double data items at consecutive addresses starting from the specified address.
- **`create_dword_at`** – Creates dword data items at consecutive addresses starting from the specified address.
- **`create_float_at`** – Creates float data items at consecutive addresses starting from the specified address.
- **`create_oword_at`** – Creates oword data items at consecutive addresses starting from the specified address.
- **`create_packed_real_at`** – Creates packed real data items at consecutive addresses starting
- **`create_qword_at`** – Creates qword data items at consecutive addresses starting from the specified address.
- **`create_string_at`** – Converts data at address to string type.
- **`create_struct_at`** – Creates struct data items at consecutive addresses starting from the specified address.
- **`create_tbyte_at`** – Creates tbyte data items at consecutive addresses starting from the specified address.
- **`create_word_at`** – Creates word data items at consecutive addresses starting from the specified address.
- **`create_yword_at`** – Creates yword data items at consecutive addresses starting from the specified address.
- **`create_zword_at`** – Creates zword data items at consecutive addresses starting from the specified address.
- **`delete_value_at`** – Delete value from flags. The corresponding address becomes uninitialized.
- **`find_binary_sequence`** – Find all occurrences of a binary pattern.
- **`find_bytes_between`** – Finds a byte pattern in memory.
- **`find_immediate_between`** – Finds an immediate value in instructions.
- **`find_text_between`** – Finds a text string in memory.
- **`get_all_flags_at`** – Gets all the full flags for the specified address.
- **`get_byte_at`** – Retrieves a single byte (8 bits) at the specified address.
- **`get_bytes_at`** – Gets the specified number of bytes of the program.
- **`get_cstring_at`** – Gets a C-style null-terminated string.
- **`get_data_size_at`** – Gets the size of the data item at the specified address.
- **`get_disassembly_at`** – Retrieves the disassembly text at the specified address.
- **`get_double_at`** – Retrieves a double-precision floating-point value at the specified address.
- **`get_dword_at`** – Retrieves a double word (32 bits/4 bytes) at the specified address.
- **`get_flags_at`** – Gets the flags for the specified address masked with IVL and MS_VAL
- **`get_float_at`** – Retrieves a single-precision floating-point value at the specified address.
- **`get_microcode_between`** – Retrieves the microcode of the given range.
- **`get_next_address`** – Gets the next valid address after the specified address.
- **`get_next_head`** – Gets the next head (start of data item) after the specified address.
- **`get_original_byte_at`** – Get original byte value (that was before patching).
- **`get_original_bytes_at`** – Gets the original bytes before any patches by reading individual bytes.
- **`get_original_dword_at`** – Get original dword value (that was before patching).
- **`get_original_qword_at`** – Get original qword value (that was before patching).
- **`get_original_word_at`** – Get original word value (that was before patching).
- **`get_previous_address`** – Gets the previous valid address before the specified address.
- **`get_previous_head`** – Gets the previous head (start of data item) before the specified address.
- **`get_qword_at`** – Retrieves a quad word (64 bits/8 bytes) at the specified address.
- **`get_string_at`** – Gets a string from the specified address.
- **`get_word_at`** – Retrieves a word (16 bits/2 bytes) at the specified address.
- **`has_any_flags_at`** – Checks if any of the specified flags are set at the given address.
- **`has_user_name_at`** – Checks if the address has a user-defined name.
- **`is_alignment_at`** – Checks if the address contains an alignment directive.
- **`is_byte_at`** – Checks if the address contains a byte data type.
- **`is_code_at`** – Checks if the address contains code.
- **`is_data_at`** – Checks if the address contains data.
- **`is_double_at`** – Checks if the address contains a double data type.
- **`is_dword_at`** – Checks if the address contains a dword data type.
- **`is_float_at`** – Checks if the address contains a float data type.
- **`is_flowed_at`** – Does the previous instruction exist and pass execution flow to the current byte?
- **`is_forced_operand_at`** – Is operand manually defined?
- **`is_head_at`** – Checks if the address is the start of a data item.
- **`is_manual_insn_at`** – Is the instruction overridden?
- **`is_not_tail_at`** – Checks if the address is not a tail byte.
- **`is_oword_at`** – Checks if the address contains an oword data type.
- **`is_packed_real_at`** – Checks if the address contains a packed real data type.
- **`is_qword_at`** – Checks if the address contains a qword data type.
- **`is_string_literal_at`** – Checks if the address contains a string literal data type.
- **`is_struct_at`** – Checks if the address contains a struct data type.
- **`is_tail_at`** – Checks if the address is part of a multi-byte data item.
- **`is_tbyte_at`** – Checks if the address contains a tbyte data type.
- **`is_unknown_at`** – Checks if the address contains unknown/undefined data.
- **`is_value_initialized_at`** – Check if the value at the specified address is initialized
- **`is_word_at`** – Checks if the address contains a word data type.
- **`is_yword_at`** – Checks if the address contains a yword data type.
- **`is_zword_at`** – Checks if the address contains a zword data type.
- **`patch_byte_at`** – Patch a byte of the program.
- **`patch_bytes_at`** – Patch the specified number of bytes of the program.
- **`patch_dword_at`** – Patch a dword of the program.
- **`patch_qword_at`** – Patch a qword of the program.
- **`patch_word_at`** – Patch a word of the program.
- **`revert_byte_at`** – Revert patched byte to its original value.
- **`set_byte_at`** – Sets a byte value at the specified address.
- **`set_bytes_at`** – Sets a sequence of bytes at the specified address.
- **`set_dword_at`** – Sets a double word (4 bytes) value at the specified address.
- **`set_qword_at`** – Sets a quad word (8 bytes) value at the specified address.
- **`set_word_at`** – Sets a word (2 bytes) value at the specified address.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### check_flags_at

```
check_flags_at(ea: ea_t, flag_mask: ByteFlags) -> bool

```

Checks if the specified flags are set at the given address.

Args: ea: The effective address. flag_mask: ByteFlags enum value(s) to check.

Returns: True if all specified flags are set, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### create_alignment_at

```
create_alignment_at(
    ea: ea_t, length: int, alignment: int
) -> bool

```

Create an alignment item.

Args: ea: The effective address. length: Size of the item in bytes. 0 means to infer from alignment. alignment: Alignment exponent. Example: 3 means align to 8 bytes, 0 means to infer from length.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If length or alignment are invalid.

#### create_byte_at

```
create_byte_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates byte data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating bytes. count: Number of consecutive byte elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_double_at

```
create_double_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates double data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating doubles. count: Number of consecutive double elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_dword_at

```
create_dword_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates dword data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating dwords. count: Number of consecutive dword elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_float_at

```
create_float_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates float data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating floats. count: Number of consecutive float elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_oword_at

```
create_oword_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates oword data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating owords. count: Number of consecutive oword elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_packed_real_at

```
create_packed_real_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates packed real data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating packed reals. count: Number of consecutive packed real elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_qword_at

```
create_qword_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates qword data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating qwords. count: Number of consecutive qword elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_string_at

```
create_string_at(
    ea: ea_t,
    length: Optional[int] = None,
    string_type: StringType = C,
) -> bool

```

Converts data at address to string type.

Args: ea: The effective address. length: String length (auto-detect if None). string_type: String type (default: StringType.C).

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If length is specified but not positive.

#### create_struct_at

```
create_struct_at(
    ea: ea_t, count: int, tid: int, force: bool = False
) -> bool

```

Creates struct data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating structs. count: Number of consecutive struct elements to create. tid: Structure type ID. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive or tid is invalid.

Example:

```
tif = db.types.parse_one_declaration(None, 'struct Point {int x; int y;};')
db.bytes.create_struct_at(ea, 1, tif.get_tid())

```

#### create_tbyte_at

```
create_tbyte_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates tbyte data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating tbytes. count: Number of consecutive tbyte elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_word_at

```
create_word_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates word data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating words. count: Number of consecutive word elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_yword_at

```
create_yword_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates yword data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating ywords. count: Number of consecutive yword elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### create_zword_at

```
create_zword_at(
    ea: ea_t, count: int = 1, force: bool = False
) -> bool

```

Creates zword data items at consecutive addresses starting from the specified address.

Args: ea: The effective address to start creating zwords. count: Number of consecutive zword elements to create. force: Forces creation overriding an existing item if there is one.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If count is not positive.

#### delete_value_at

```
delete_value_at(ea: ea_t) -> None

```

Delete value from flags. The corresponding address becomes uninitialized.

Args: ea: The effective address.

Raises: InvalidEAError: If the effective address is invalid.

#### find_binary_sequence

```
find_binary_sequence(
    pattern: bytes,
    start_ea: ea_t = None,
    end_ea: ea_t = None,
) -> List[ea_t]

```

Find all occurrences of a binary pattern.

Args: pattern: Binary pattern to search for. start_ea: Search start address; defaults to database minimum ea if None. end_ea: Search end address; defaults to database maximum ea if None.

Returns: List of addresses where pattern was found.

Raises: InvalidParameterError: If pattern is invalid. InvalidEAError: If start_ea or end_ea are specified but invalid.

#### find_bytes_between

```
find_bytes_between(
    pattern: bytes,
    start_ea: ea_t = None,
    end_ea: ea_t = None,
) -> Optional[ea_t]

```

Finds a byte pattern in memory.

Args: pattern: Byte pattern to search for. start_ea: Search start address; defaults to database minimum ea if None end_ea: Search end address; defaults to database maximum ea if None

Returns: Address where pattern was found, or None if not found.

Raises: InvalidParameterError: If pattern or interval are invalid. InvalidEAError: If start_ea or end_ea are specified but invalid.

#### find_immediate_between

```
find_immediate_between(
    value: int, start_ea: ea_t = None, end_ea: ea_t = None
) -> Optional[ea_t]

```

Finds an immediate value in instructions.

Args: value: Immediate value to search for. start_ea: Search start address; defaults to database minimum ea if None end_ea: Search end address; defaults to database maximum ea if None

Returns: Address where immediate was found, or None if not found.

Raises: InvalidParameterError: If value is not an integer. InvalidEAError: If start_ea or end_ea are specified but invalid.

#### find_text_between

```
find_text_between(
    text: str,
    start_ea: ea_t = None,
    end_ea: ea_t = None,
    flags: SearchFlags = DOWN,
) -> Optional[ea_t]

```

Finds a text string in memory.

Args: text: Text to search for. start_ea: Search Start address; defaults to database minimum ea if None end_ea: Search end address; defaults to database maximum ea if None flags: Search flags (default: SearchFlags.DOWN).

Returns: Address where text was found, or None if not found.

Raises: InvalidParameterError: If text or interval are invalid. InvalidEAError: If start_ea or end_ea are specified but invalid.

#### get_all_flags_at

```
get_all_flags_at(ea: ea_t) -> ByteFlags

```

Gets all the full flags for the specified address.

Args: ea: The effective address.

Returns: ByteFlags enum value representing the full flags.

Raises: InvalidEAError: If the effective address is invalid.

#### get_byte_at

```
get_byte_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> int

```

Retrieves a single byte (8 bits) at the specified address.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The byte value (0-255).

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value.

#### get_bytes_at

```
get_bytes_at(ea: ea_t, size: int) -> Optional[bytes]

```

Gets the specified number of bytes of the program.

Args: ea: The effective address. size: Number of bytes to read.

Returns: The bytes (as bytes object), or None in case of failure

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If size is not positive.

#### get_cstring_at

```
get_cstring_at(
    ea: ea_t, max_length: int = 1024
) -> Optional[str]

```

Gets a C-style null-terminated string.

Args: ea: The effective address. max_length: Maximum string length to read (default: 1024).

Returns: The string if it was successfully extracted or None in case of error

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If max_length is not positive.

#### get_data_size_at

```
get_data_size_at(ea: ea_t) -> int

```

Gets the size of the data item at the specified address.

Args: ea: The effective address.

Returns: Size of the data item in bytes.

Raises: InvalidEAError: If the effective address is invalid.

#### get_disassembly_at

```
get_disassembly_at(
    ea: ea_t, remove_tags: bool = True
) -> Optional[str]

```

Retrieves the disassembly text at the specified address.

Args: ea: The effective address. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: The disassembly string, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid.

#### get_double_at

```
get_double_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> Optional[float]

```

Retrieves a double-precision floating-point value at the specified address.

Best-effort implementation that may fail on some architectures or non-standard floating-point formats.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The double value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value. UnsupportedValueError: If the floating-point format is not supported

Note: Only works for standard IEEE 754 32-bit and 64-bit floats. May not work on embedded systems or architectures with custom floating-point representations.

#### get_dword_at

```
get_dword_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> int

```

Retrieves a double word (32 bits/4 bytes) at the specified address.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The dword value.

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value.

#### get_flags_at

```
get_flags_at(ea: ea_t) -> ByteFlags

```

Gets the flags for the specified address masked with IVL and MS_VAL

Args: ea: The effective address.

Returns: ByteFlags enum value representing the flags.

Raises: InvalidEAError: If the effective address is invalid.

#### get_float_at

```
get_float_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> Optional[float]

```

Retrieves a single-precision floating-point value at the specified address.

Best-effort implementation that may fail on some architectures or non-standard floating-point formats.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The float value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value. UnsupportedValueError: If the floating-point format is not supported

Note: Only works for standard IEEE 754 32-bit and 64-bit floats. May not work on embedded systems or architectures with custom floating-point representations.

#### get_microcode_between

```
get_microcode_between(
    start_ea: ea_t, end_ea: ea_t, remove_tags: bool = True
) -> List[str]

```

Retrieves the microcode of the given range.

Args: start_ea: The range start. end_ea: The range end. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: A list of strings, each representing a line of microcode. Returns empty list if range is invalid or decompilation fails.

Raises: RuntimeError: If microcode generation fails for the range.

#### get_next_address

```
get_next_address(ea: ea_t) -> Optional[ea_t]

```

Gets the next valid address after the specified address.

Args: ea: The effective address.

Returns: Next valid address or None.

Raises: InvalidEAError: If the effective address is invalid.

#### get_next_head

```
get_next_head(
    ea: ea_t, max_ea: ea_t = None
) -> Optional[ea_t]

```

Gets the next head (start of data item) after the specified address.

Args: ea: The effective address. max_ea: Maximum address to search.

Returns: Address of next head, or None if not found.

Raises: InvalidEAError: If the effective address is invalid.

#### get_original_byte_at

```
get_original_byte_at(ea: ea_t) -> Optional[int]

```

Get original byte value (that was before patching).

Args: ea: The effective address.

Returns: The original byte value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid.

#### get_original_bytes_at

```
get_original_bytes_at(
    ea: ea_t, size: int
) -> Optional[bytes]

```

Gets the original bytes before any patches by reading individual bytes.

Args: ea: The effective address. size: Number of bytes to read.

Returns: The original bytes or None in case of error.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If size is not positive.

#### get_original_dword_at

```
get_original_dword_at(ea: ea_t) -> Optional[int]

```

Get original dword value (that was before patching).

Args: ea: The effective address.

Returns: The original dword value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid.

#### get_original_qword_at

```
get_original_qword_at(ea: ea_t) -> Optional[int]

```

Get original qword value (that was before patching).

Args: ea: The effective address.

Returns: The original qword value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid.

#### get_original_word_at

```
get_original_word_at(ea: ea_t) -> Optional[int]

```

Get original word value (that was before patching).

Args: ea: The effective address.

Returns: The original word value, or None if an error occurs.

Raises: InvalidEAError: If the effective address is invalid.

#### get_previous_address

```
get_previous_address(ea: ea_t) -> Optional[ea_t]

```

Gets the previous valid address before the specified address.

Args: ea: The effective address.

Returns: Previous valid address.

Raises: InvalidEAError: If the effective address is invalid.

#### get_previous_head

```
get_previous_head(
    ea: ea_t, min_ea: ea_t = None
) -> Optional[ea_t]

```

Gets the previous head (start of data item) before the specified address.

Args: ea: The effective address. min_ea: Minimum address to search.

Returns: Address of previous head, or None if not found.

Raises: InvalidEAError: If the effective address is invalid.

#### get_qword_at

```
get_qword_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> int

```

Retrieves a quad word (64 bits/8 bytes) at the specified address.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The qword value.

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value.

#### get_string_at

```
get_string_at(
    ea: ea_t, max_length: Optional[int] = None
) -> Optional[str]

```

Gets a string from the specified address.

Args: ea: The effective address. max_length: Maximum string length to read.

Returns: The string if it was successfully extracted or None in case of error

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If max_length is specified but not positive.

#### get_word_at

```
get_word_at(
    ea: ea_t, allow_uninitialized: bool = False
) -> int

```

Retrieves a word (16 bits/2 bytes) at the specified address.

Args: ea: The effective address. allow_uninitialized: If True, allows reading addresses with uninitialized values.

Returns: The word value.

Raises: InvalidEAError: If the effective address is invalid. NoValueError: If allow_uninitialized is False and the address contains an uninitialized value.

#### has_any_flags_at

```
has_any_flags_at(ea: ea_t, flag_mask: ByteFlags) -> bool

```

Checks if any of the specified flags are set at the given address.

Args: ea: The effective address. flag_mask: ByteFlags enum value(s) to check.

Returns: True if any of the specified flags are set, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### has_user_name_at

```
has_user_name_at(ea: ea_t) -> bool

```

Checks if the address has a user-defined name.

Args: ea: The effective address.

Returns: True if has user name, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_alignment_at

```
is_alignment_at(ea: ea_t) -> bool

```

Checks if the address contains an alignment directive.

Args: ea: The effective address.

Returns: True if alignment type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_byte_at

```
is_byte_at(ea: ea_t) -> bool

```

Checks if the address contains a byte data type.

Args: ea: The effective address.

Returns: True if byte type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_code_at

```
is_code_at(ea: ea_t) -> bool

```

Checks if the address contains code.

Args: ea: The effective address.

Returns: True if code, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_data_at

```
is_data_at(ea: ea_t) -> bool

```

Checks if the address contains data.

Args: ea: The effective address.

Returns: True if data, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_double_at

```
is_double_at(ea: ea_t) -> bool

```

Checks if the address contains a double data type.

Args: ea: The effective address.

Returns: True if double type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_dword_at

```
is_dword_at(ea: ea_t) -> bool

```

Checks if the address contains a dword data type.

Args: ea: The effective address.

Returns: True if dword type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_float_at

```
is_float_at(ea: ea_t) -> bool

```

Checks if the address contains a float data type.

Args: ea: The effective address.

Returns: True if float type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_flowed_at

```
is_flowed_at(ea: ea_t) -> bool

```

Does the previous instruction exist and pass execution flow to the current byte?

Args: ea: The effective address.

Returns: True if flow, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_forced_operand_at

```
is_forced_operand_at(ea: ea_t, n: int) -> bool

```

Is operand manually defined?

Args: ea: The effective address. n: Operand number (0-based).

Returns: True if operand is forced, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If operand number is negative.

#### is_head_at

```
is_head_at(ea: ea_t) -> bool

```

Checks if the address is the start of a data item.

Args: ea: The effective address.

Returns: True if head, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_manual_insn_at

```
is_manual_insn_at(ea: ea_t) -> bool

```

Is the instruction overridden?

Args: ea: The effective address.

Returns: True if instruction is manually overridden, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_not_tail_at

```
is_not_tail_at(ea: ea_t) -> bool

```

Checks if the address is not a tail byte.

Args: ea: The effective address.

Returns: True if not tail, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_oword_at

```
is_oword_at(ea: ea_t) -> bool

```

Checks if the address contains an oword data type.

Args: ea: The effective address.

Returns: True if oword type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_packed_real_at

```
is_packed_real_at(ea: ea_t) -> bool

```

Checks if the address contains a packed real data type.

Args: ea: The effective address.

Returns: True if packed real type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_qword_at

```
is_qword_at(ea: ea_t) -> bool

```

Checks if the address contains a qword data type.

Args: ea: The effective address.

Returns: True if qword type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_string_literal_at

```
is_string_literal_at(ea: ea_t) -> bool

```

Checks if the address contains a string literal data type.

Args: ea: The effective address.

Returns: True if string literal type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_struct_at

```
is_struct_at(ea: ea_t) -> bool

```

Checks if the address contains a struct data type.

Args: ea: The effective address.

Returns: True if struct type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_tail_at

```
is_tail_at(ea: ea_t) -> bool

```

Checks if the address is part of a multi-byte data item.

Args: ea: The effective address.

Returns: True if tail, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_tbyte_at

```
is_tbyte_at(ea: ea_t) -> bool

```

Checks if the address contains a tbyte data type.

Args: ea: The effective address.

Returns: True if tbyte type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_unknown_at

```
is_unknown_at(ea: ea_t) -> bool

```

Checks if the address contains unknown/undefined data.

Args: ea: The effective address.

Returns: True if unknown, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_value_initialized_at

```
is_value_initialized_at(ea: ea_t) -> bool

```

Check if the value at the specified address is initialized

Args: ea: The effective address.

Returns: True if byte is loaded, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_word_at

```
is_word_at(ea: ea_t) -> bool

```

Checks if the address contains a word data type.

Args: ea: The effective address.

Returns: True if word type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_yword_at

```
is_yword_at(ea: ea_t) -> bool

```

Checks if the address contains a yword data type.

Args: ea: The effective address.

Returns: True if yword type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_zword_at

```
is_zword_at(ea: ea_t) -> bool

```

Checks if the address contains a zword data type.

Args: ea: The effective address.

Returns: True if zword type, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### patch_byte_at

```
patch_byte_at(ea: ea_t, value: int) -> bool

```

Patch a byte of the program. The original value is saved and can be obtained by get_original_byte_at().

Args: ea: The effective address. value: Byte value to patch.

Returns: True if the database has been modified, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid byte (0-0xFF).

#### patch_bytes_at

```
patch_bytes_at(ea: ea_t, data: bytes) -> None

```

Patch the specified number of bytes of the program. Original values are saved and available with get_original_bytes_at().

Args: ea: The effective address. data: Bytes to patch.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If data is not bytes or is empty.

#### patch_dword_at

```
patch_dword_at(ea: ea_t, value: int) -> bool

```

Patch a dword of the program. The original value is saved and can be obtained by get_original_dword_at().

Args: ea: The effective address. value: Dword value to patch.

Returns: True if the database has been modified, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid dword (0-0xFFFFFFFF).

#### patch_qword_at

```
patch_qword_at(ea: ea_t, value: int) -> bool

```

Patch a qword of the program. The original value is saved and can be obtained by get_original_qword_at().

Args: ea: The effective address. value: Qword value to patch.

Returns: True if the database has been modified, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid qword (0-0xFFFFFFFFFFFFFFFF).

#### patch_word_at

```
patch_word_at(ea: ea_t, value: int) -> bool

```

Patch a word of the program. The original value is saved and can be obtained by get_original_word_at().

Args: ea: The effective address. value: Word value to patch.

Returns: True if the database has been modified, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid word (0-0xFFFF).

#### revert_byte_at

```
revert_byte_at(ea: ea_t) -> bool

```

Revert patched byte to its original value.

Args: ea: The effective address.

Returns: True if byte was patched before and reverted now, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### set_byte_at

```
set_byte_at(ea: ea_t, value: int) -> bool

```

Sets a byte value at the specified address.

Args: ea: The effective address. value: Byte value to set.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid byte (0-0xFF).

#### set_bytes_at

```
set_bytes_at(ea: ea_t, data: bytes) -> None

```

Sets a sequence of bytes at the specified address.

Args: ea: The effective address. data: Bytes to write.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If data is not bytes or is empty.

#### set_dword_at

```
set_dword_at(ea: ea_t, value: int) -> None

```

Sets a double word (4 bytes) value at the specified address.

Args: ea: The effective address. value: Double word value to set.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid dword (0-0xFFFFFFFF).

#### set_qword_at

```
set_qword_at(ea: ea_t, value: int) -> None

```

Sets a quad word (8 bytes) value at the specified address.

Args: ea: The effective address. value: Quad word value to set.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid qword (0-0xFFFFFFFFFFFFFFFF).

#### set_word_at

```
set_word_at(ea: ea_t, value: int) -> None

```

Sets a word (2 bytes) value at the specified address.

Args: ea: The effective address. value: Word value to set.

Raises: InvalidEAError: If the effective address is invalid. InvalidParameterError: If value is not a valid word (0-0xFFFF).

### NoValueError

```
NoValueError(ea: ea_t)

```

Bases: `ValueError`

Raised when a read operation is attempted on an uninitialized address.

### SearchFlags

Bases: `IntFlag`

Search flags for text and pattern searching.

Attributes:

- **`BRK`** – Return BADADDR if the search was cancelled.
- **`CASE`** – Case-sensitive search (case-insensitive otherwise)
- **`DOWN`** – Search towards higher addresses
- **`IDENT`** – Search for an identifier (text search). It means that the
- **`NOBRK`** – Don't test if the user interrupted the search
- **`NOSHOW`** – Don't display the search progress/refresh screen
- **`REGEX`** – Regular expressions in search string
- **`UP`** – Search towards lower addresses

#### BRK

```
BRK = SEARCH_BRK

```

Return BADADDR if the search was cancelled.

#### CASE

```
CASE = SEARCH_CASE

```

Case-sensitive search (case-insensitive otherwise)

#### DOWN

```
DOWN = SEARCH_DOWN

```

Search towards higher addresses

#### IDENT

```
IDENT = SEARCH_IDENT

```

Search for an identifier (text search). It means that the characters before and after the match cannot be is_visible_char().

#### NOBRK

```
NOBRK = SEARCH_NOBRK

```

Don't test if the user interrupted the search

#### NOSHOW

```
NOSHOW = SEARCH_NOSHOW

```

Don't display the search progress/refresh screen

#### REGEX

```
REGEX = SEARCH_REGEX

```

Regular expressions in search string

#### UP

```
UP = SEARCH_UP

```

Search towards lower addresses

### UnsupportedValueError

```
UnsupportedValueError(message: str)

```

Bases: `ValueError`

Raised when a read operation is attempted on a value which has an unsupported format.

# `Comments`

## comments

Classes:

- **`CommentInfo`** – Represents information about a Comment.
- **`CommentKind`** – Enumeration for IDA comment types.
- **`Comments`** – Provides access to user-defined comments in the IDA database.
- **`ExtraCommentKind`** – Enumeration for extra comment positions.

### CommentInfo

```
CommentInfo(ea: ea_t, comment: str, repeatable: bool)

```

Represents information about a Comment.

Attributes:

- **`comment`** (`str`) –
- **`ea`** (`ea_t`) –
- **`repeatable`** (`bool`) –

#### comment

```
comment: str

```

#### ea

```
ea: ea_t

```

#### repeatable

```
repeatable: bool

```

### CommentKind

Bases: `Enum`

Enumeration for IDA comment types.

Attributes:

- **`ALL`** –
- **`REGULAR`** –
- **`REPEATABLE`** –

#### ALL

```
ALL = 'all'

```

#### REGULAR

```
REGULAR = 'regular'

```

#### REPEATABLE

```
REPEATABLE = 'repeatable'

```

### Comments

```
Comments(database: Database)

```

Bases: `DatabaseEntity`

Provides access to user-defined comments in the IDA database.

Can be used to iterate over all comments in the opened database.

IDA supports two types of comments:

- Regular comments: Displayed at specific addresses
- Repeatable comments: Displayed at all references to the same address

Args: database: Reference to the active IDA database.

Methods:

- **`delete_at`** – Deletes a comment at the specified address.
- **`delete_extra_at`** – Deletes a specific extra comment.
- **`get_all`** – Creates an iterator for comments in the database.
- **`get_all_extra_at`** – Gets all extra comments of a specific kind.
- **`get_at`** – Retrieves the comment at the specified address.
- **`get_extra_at`** – Gets a specific extra comment.
- **`set_at`** – Sets a comment at the specified address.
- **`set_extra_at`** – Sets an extra comment at the specified address and index.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### delete_at

```
delete_at(
    ea: int, comment_kind: CommentKind = REGULAR
) -> None

```

Deletes a comment at the specified address.

Args: ea: The effective address. comment_kind: Type of comment to delete (REGULAR or REPEATABLE).

Raises: InvalidEAError: If the effective address is invalid.

#### delete_extra_at

```
delete_extra_at(
    ea: int, index: int, kind: ExtraCommentKind
) -> bool

```

Deletes a specific extra comment.

Args: ea: The effective address. index: The comment index (0-based). kind: ANTERIOR or POSTERIOR.

Raises: InvalidEAError: If the effective address is invalid.

Returns: True if successful.

#### get_all

```
get_all(
    comment_kind: CommentKind = REGULAR,
) -> Iterator[CommentInfo]

```

Creates an iterator for comments in the database.

Args: comment_kind: Type of comments to retrieve:

- CommentKind.REGULAR: Only regular comments
- CommentKind.REPEATABLE: Only repeatable comments
- CommentKind.ALL: Both regular and repeatable comments

Yields: Tuples of (address, comment_text, is_repeatable) for each comment found.

#### get_all_extra_at

```
get_all_extra_at(
    ea: int, kind: ExtraCommentKind
) -> Iterator[str]

```

Gets all extra comments of a specific kind.

Args: ea: The effective address. kind: ANTERIOR or POSTERIOR.

Raises: InvalidEAError: If the effective address is invalid.

Yields: Comment strings in order.

#### get_at

```
get_at(
    ea: ea_t, comment_kind: CommentKind = REGULAR
) -> Optional[CommentInfo]

```

Retrieves the comment at the specified address.

Args: ea: The effective address. comment_kind: Type of comment to retrieve (REGULAR or REPEATABLE).

Raises: InvalidEAError: If the effective address is invalid.

Returns: The comment string, or None if no comment exists.

#### get_extra_at

```
get_extra_at(
    ea: int, index: int, kind: ExtraCommentKind
) -> Optional[str]

```

Gets a specific extra comment.

Args: ea: The effective address. index: The comment index (0-based). kind: ANTERIOR or POSTERIOR.

Raises: InvalidEAError: If the effective address is invalid.

Returns: The comment text or None if not found.

#### set_at

```
set_at(
    ea: int,
    comment: str,
    comment_kind: CommentKind = REGULAR,
) -> bool

```

Sets a comment at the specified address.

Args: ea: The effective address. comment: The comment text to assign. comment_kind: Type of comment to set (REGULAR or REPEATABLE).

Raises: InvalidEAError: If the effective address is invalid.

Returns: True if the comment was successfully set, False otherwise.

#### set_extra_at

```
set_extra_at(
    ea: int,
    index: int,
    comment: str,
    kind: ExtraCommentKind,
) -> bool

```

Sets an extra comment at the specified address and index.

Args: ea: The effective address. index: The comment index (0-based). comment: The comment text. kind: ANTERIOR or POSTERIOR.

Raises: InvalidEAError: If the effective address is invalid.

Returns: True if successful.

### ExtraCommentKind

Bases: `Enum`

Enumeration for extra comment positions.

Attributes:

- **`ANTERIOR`** –
- **`POSTERIOR`** –

#### ANTERIOR

```
ANTERIOR = 'anterior'

```

#### POSTERIOR

```
POSTERIOR = 'posterior'

```

# `Database`

## database

Classes:

- **`CompilerInformation`** – Compiler information for the current database.
- **`Database`** – Provides access and control over the loaded IDA database.
- **`DatabaseError`** – Exception for database operations.
- **`DatabaseMetadata`** – Metadata information about the current database.
- **`ExecutionMode`** – Enumeration Execution Modes
- **`IdaCommandOptions`** – Configuration for building IDA command line arguments.

### CompilerInformation

```
CompilerInformation(
    name: str,
    byte_size_bits: int,
    short_size_bits: int,
    enum_size_bits: int,
    int_size_bits: int,
    long_size_bits: int,
    double_size_bits: int,
    long_long_size_bits: int,
)

```

Compiler information for the current database.

Attributes:

- **`byte_size_bits`** (`int`) –
- **`double_size_bits`** (`int`) –
- **`enum_size_bits`** (`int`) –
- **`int_size_bits`** (`int`) –
- **`long_long_size_bits`** (`int`) –
- **`long_size_bits`** (`int`) –
- **`name`** (`str`) –
- **`short_size_bits`** (`int`) –

#### byte_size_bits

```
byte_size_bits: int

```

#### double_size_bits

```
double_size_bits: int

```

#### enum_size_bits

```
enum_size_bits: int

```

#### int_size_bits

```
int_size_bits: int

```

#### long_long_size_bits

```
long_long_size_bits: int

```

#### long_size_bits

```
long_size_bits: int

```

#### name

```
name: str

```

#### short_size_bits

```
short_size_bits: int

```

### Database

```
Database(hooks: Optional[HooksList] = None)

```

Provides access and control over the loaded IDA database.

This class supports context manager protocol for automatic resource cleanup. When used as a context manager, the database is automatically closed on exit.

Args: hooks (HooksList, optional): A list of hook instances to associate with this database. Defaults to an empty list.

Warning: Direct instantiation is discouraged. Use `Database.open()` instead.

```
Database lifecycle behavior differs based on execution context:
- Library mode: You can open/close databases programmatically
- IDA mode: You can only obtain a handle to the currently open database
  by calling `Database.open()` without arguments

```

Example:

```
    # Library mode: Open and automatically close a database
    with Database.open("path/to/file.exe", save_on_close=True) as db:
        print(f"Loaded: {db.path}")
    # Database is automatically closed here

    # Library mode: Manual control
    db = Database.open("path/to/file.exe", save_on_close=True)
    db.close()

    # IDA mode: Get handle to current database
    db = Database.open()  # or Database.open(None)

```

Methods:

- **`close`** – Closes the currently open database.
- **`execute_script`** – Execute the specified python script
- **`hook`** – Activate (hook) all registered event handler instances.
- **`is_open`** – Checks if the database is loaded.
- **`is_valid_ea`** – Check if the specified address is valid.
- **`open`** – Opens or connects to an IDA database.
- **`unhook`** – Deactivate (unhook) all registered event handler instances.

Attributes:

- **`architecture`** (`Optional[str]`) – The processor architecture.
- **`base_address`** (`Optional[ea_t]`) – The image base address of this database.
- **`bitness`** (`Optional[int]`) – The application bitness (32/64).
- **`bytes`** (`Bytes`) – Handler that provides access to byte-level memory operations.
- **`comments`** (`Comments`) – Handler that provides access to user comment-related operations.
- **`compiler_information`** (`CompilerInformation`) – Compiler information for current database.
- **`crc32`** (`Optional[int]`) – The CRC32 checksum of the input file.
- **`current_ea`** (`ea_t`) – The current effective address (equivalent to the "screen EA" in IDA GUI).
- **`entries`** (`Entries`) – Handler that provides access to entries operations.
- **`execution_mode`** (`ExecutionMode`) – The execution mode, user or kernel mode.
- **`filesize`** (`Optional[int]`) – The input file size.
- **`format`** (`Optional[str]`) – The file format type.
- **`functions`** (`Functions`) – Handler that provides access to function-related operations.
- **`heads`** (`Heads`) – Handler that provides access to user heads operations.
- **`hooks`** (`HooksList`) – Returns the list of associated hook instances.
- **`instructions`** (`Instructions`) – Handler that provides access to instruction-related operations.
- **`load_time`** (`Optional[str]`) – The database load time.
- **`maximum_ea`** (`ea_t`) – The maximum effective address from this database.
- **`md5`** (`Optional[str]`) – The MD5 hash of the input file.
- **`metadata`** (`DatabaseMetadata`) – Map of key-value metadata about the current database.
- **`minimum_ea`** (`ea_t`) – The minimum effective address from this database.
- **`module`** (`Optional[str]`) – The module name.
- **`names`** (`Names`) – Handler that provides access to name-related operations.
- **`path`** (`Optional[str]`) – The input file path.
- **`save_on_close`** –
- **`segments`** (`Segments`) – Handler that provides access to memory segment-related operations.
- **`sha256`** (`Optional[str]`) – The SHA256 hash of the input file.
- **`signature_files`** (`SignatureFiles`) – Handler that provides access to signature file operations.
- **`start_ip`** (`ea_t`) – The start instruction pointer value
- **`strings`** (`Strings`) – Handler that provides access to string-related operations.
- **`types`** (`Types`) – Handler that provides access to type-related operations.
- **`xrefs`** (`Xrefs`) – Handler that provides access to cross-reference (xref) operations.

#### architecture

```
architecture: Optional[str]

```

The processor architecture.

#### base_address

```
base_address: Optional[ea_t]

```

The image base address of this database.

#### bitness

```
bitness: Optional[int]

```

The application bitness (32/64).

#### bytes

```
bytes: Bytes

```

Handler that provides access to byte-level memory operations.

#### comments

```
comments: Comments

```

Handler that provides access to user comment-related operations.

#### compiler_information

```
compiler_information: CompilerInformation

```

Compiler information for current database.

#### crc32

```
crc32: Optional[int]

```

The CRC32 checksum of the input file.

#### current_ea

```
current_ea: ea_t

```

The current effective address (equivalent to the "screen EA" in IDA GUI).

#### entries

```
entries: Entries

```

Handler that provides access to entries operations.

#### execution_mode

```
execution_mode: ExecutionMode

```

The execution mode, user or kernel mode.

#### filesize

```
filesize: Optional[int]

```

The input file size.

#### format

```
format: Optional[str]

```

The file format type.

#### functions

```
functions: Functions

```

Handler that provides access to function-related operations.

#### heads

```
heads: Heads

```

Handler that provides access to user heads operations.

#### hooks

```
hooks: HooksList

```

Returns the list of associated hook instances.

#### instructions

```
instructions: Instructions

```

Handler that provides access to instruction-related operations.

#### load_time

```
load_time: Optional[str]

```

The database load time.

#### maximum_ea

```
maximum_ea: ea_t

```

The maximum effective address from this database.

#### md5

```
md5: Optional[str]

```

The MD5 hash of the input file.

#### metadata

```
metadata: DatabaseMetadata

```

Map of key-value metadata about the current database. Dynamically built from DatabaseMetadata dataclass fields. Returns metadata with original property types preserved.

#### minimum_ea

```
minimum_ea: ea_t

```

The minimum effective address from this database.

#### module

```
module: Optional[str]

```

The module name.

#### names

```
names: Names

```

Handler that provides access to name-related operations.

#### path

```
path: Optional[str]

```

The input file path.

#### save_on_close

```
save_on_close = True

```

#### segments

```
segments: Segments

```

Handler that provides access to memory segment-related operations.

#### sha256

```
sha256: Optional[str]

```

The SHA256 hash of the input file.

#### signature_files

```
signature_files: SignatureFiles

```

Handler that provides access to signature file operations.

#### start_ip

```
start_ip: ea_t

```

The start instruction pointer value

#### strings

```
strings: Strings

```

Handler that provides access to string-related operations.

#### types

```
types: Types

```

Handler that provides access to type-related operations.

#### xrefs

```
xrefs: Xrefs

```

Handler that provides access to cross-reference (xref) operations.

#### close

```
close(save: Optional[bool] = None) -> None

```

Closes the currently open database.

Args: save: If provided, saves/discards changes accordingly. If None, uses the save_on_close setting from open().

Note: This function is available only when running IDA as a library. When running inside the IDA GUI, we have no control on the database lifecycle.

#### execute_script

```
execute_script(file_path: str) -> None

```

Execute the specified python script

Args: file_path: The script file path

Raises: RuntimeError: If script execution fails.

#### hook

```
hook() -> None

```

Activate (hook) all registered event handler instances.

This method associates each hook instance with the current database instance and calls their `hook()` method. Hooks are automatically hooked when the database is opened (including when used as a context manager).

Typically, you do not need to call this method manually—hooks are managed automatically upon database entry.

#### is_open

```
is_open() -> bool

```

Checks if the database is loaded.

Returns: True if a database is open, false otherwise.

#### is_valid_ea

```
is_valid_ea(ea: ea_t, strict_check: bool = True) -> bool

```

Check if the specified address is valid.

Args: ea: The effective address to validate. strict_check: If True, validates ea is mapped (ida_bytes.is_mapped). If False, only validates ea is within database range.

Returns: True if address is valid according to the check level.

#### open

```
open(
    path: str = '',
    args: Optional[IdaCommandOptions] = None,
    save_on_close: bool = True,
    hooks: Optional[HooksList] = None,
) -> Database

```

Opens or connects to an IDA database.

This method has two distinct behaviors depending on the execution context:

**Library mode** (IDA as a library): Opens a new database from the specified file path. Full control over the database lifecycle including opening and closing.

**IDA GUI mode** (running inside IDA): Returns a handle to the currently open database. Set `path` to None.

Args: path: Path to the binary file to analyze.

- Library mode: Required path to the file
- IDA GUI mode: Must be None to reference the currently open database Defaults to None. args: Additional arguments to pass to the IDA kernel when opening the database (e.g., processor type, loading address, analysis options). Only applicable in library mode. Defaults to None. save_on_close: Whether to save changes when closing the database. This is used automatically when exiting a context manager, but can be overridden in explicit `close()` calls. Defaults to False. hooks: List of hook instances to associate with the database. Hooks are automatically enabled before opening and disabled after closing. Defaults to an empty list.

Returns: Database: A Database instance connected to the specified or current database.

Raises: DatabaseError: If the database cannot be opened or if `path` is provided when running inside IDA GUI.

Example:

```
    # Library mode: Open a new database with custom options
    with Database.open(
        "malware.exe",
        args={"processor": "arm", "load_addr": 0x1000},
        save_on_close=True
    ) as db:
        # Analyze the binary
        pass  # Automatically saved and closed

    # IDA GUI mode: Get current database
    db = Database.open()  # path=None
    # Work with the currently open database

```

#### unhook

```
unhook() -> None

```

Deactivate (unhook) all registered event handler instances.

This method calls `unhook()` on each registered hook and disassociates them from the database instance. Hooks are automatically unhooked when the database is closed, including when used with the database as a context manager.

Typically, you do not need to call this method manually—hooks are managed automatically upon database exit.

### DatabaseError

Bases: `Exception`

Exception for database operations.

### DatabaseMetadata

```
DatabaseMetadata(
    path: Optional[str] = None,
    module: Optional[str] = None,
    base_address: Optional[ea_t] = None,
    filesize: Optional[int] = None,
    md5: Optional[str] = None,
    sha256: Optional[str] = None,
    crc32: Optional[int] = None,
    architecture: Optional[str] = None,
    bitness: Optional[int] = None,
    format: Optional[str] = None,
    load_time: Optional[str] = None,
    compiler_information: Optional[str] = None,
    execution_mode: Optional[str] = None,
)

```

Metadata information about the current database.

Attributes:

- **`architecture`** (`Optional[str]`) –
- **`base_address`** (`Optional[ea_t]`) –
- **`bitness`** (`Optional[int]`) –
- **`compiler_information`** (`Optional[str]`) –
- **`crc32`** (`Optional[int]`) –
- **`execution_mode`** (`Optional[str]`) –
- **`filesize`** (`Optional[int]`) –
- **`format`** (`Optional[str]`) –
- **`load_time`** (`Optional[str]`) –
- **`md5`** (`Optional[str]`) –
- **`module`** (`Optional[str]`) –
- **`path`** (`Optional[str]`) –
- **`sha256`** (`Optional[str]`) –

#### architecture

```
architecture: Optional[str] = None

```

#### base_address

```
base_address: Optional[ea_t] = None

```

#### bitness

```
bitness: Optional[int] = None

```

#### compiler_information

```
compiler_information: Optional[str] = None

```

#### crc32

```
crc32: Optional[int] = None

```

#### execution_mode

```
execution_mode: Optional[str] = None

```

#### filesize

```
filesize: Optional[int] = None

```

#### format

```
format: Optional[str] = None

```

#### load_time

```
load_time: Optional[str] = None

```

#### md5

```
md5: Optional[str] = None

```

#### module

```
module: Optional[str] = None

```

#### path

```
path: Optional[str] = None

```

#### sha256

```
sha256: Optional[str] = None

```

### ExecutionMode

Bases: `Enum`

Enumeration Execution Modes

Attributes:

- **`Kernel`** –
- **`User`** –

#### Kernel

```
Kernel = 'Kernel Mode'

```

#### User

```
User = 'User Mode'

```

### IdaCommandOptions

```
IdaCommandOptions(
    auto_analysis: bool = True,
    loading_address: Optional[int] = None,
    new_database: bool = False,
    compiler: Optional[str] = None,
    first_pass_directives: List[str] = list(),
    second_pass_directives: List[str] = list(),
    disable_fpp: bool = False,
    entry_point: Optional[int] = None,
    jit_debugger: Optional[bool] = None,
    log_file: Optional[str] = None,
    disable_mouse: bool = False,
    plugin_options: Optional[str] = None,
    output_database: Optional[str] = None,
    processor: Optional[str] = None,
    db_compression: Optional[str] = None,
    run_debugger: Optional[str] = None,
    load_resources: bool = False,
    script_file: Optional[str] = None,
    script_args: List[str] = list(),
    file_type: Optional[str] = None,
    file_member: Optional[str] = None,
    empty_database: bool = False,
    windows_dir: Optional[str] = None,
    no_segmentation: bool = False,
    debug_flags: Union[int, List[str]] = 0,
)

```

Configuration for building IDA command line arguments.

Set the desired options as attributes, then call `build_args()` to generate the command line string. Attributes correspond to IDA switches.

Example:

```
opts = IdaCommandOptions(
    auto_analysis=False,
    processor="arm",
    script_file="myscript.py",
    script_args=["arg1", "arg2"],
    debug_flags=["queue", "debugger"]
)
args = opts.build_args()

```

Attributes: auto_analysis (bool): If False, disables auto analysis (-a). Default: True (auto analysis enabled). loading_address (Optional[int]): Address (in paragraphs, 16 bytes each) to load the file at (-b). Default: None (not set). new_database (bool): If True, deletes the old database and creates a new one (-c). Default: False. compiler (Optional[str]): Compiler identifier string for the database (-C). Default: None. first_pass_directives (List[str]): Directives for first pass configuration (-d). Default: []. second_pass_directives (List[str]): Directives for second pass configuration (-D). Default: []. disable_fpp (bool): If True, disables FPP instructions (IBM PC only) (-f). Default: False. entry_point (Optional[int]): Entry point address (-i). Default: None (not set). jit_debugger (Optional[bool]): If set, enables/disables IDA as just-in-time debugger (-I). Default: None. log_file (Optional[str]): Path to the log file (-L). Default: None. disable_mouse (bool): If True, disables mouse support in text mode (-M). Default: False. plugin_options (Optional[str]): Options to pass to plugins (-O). Default: None. output_database (Optional[str]): Output database path (-o). Implies new_database. Default: None. processor (Optional[str]): Processor type identifier (-p). Default: None. db_compression (Optional[str]): Database compression ('compress', 'pack', 'no_pack') (-P). Default: None. run_debugger (Optional[str]): Debugger options string to run immediately (-r). Default: None. load_resources (bool): If True, loads MS Windows exe resources (-R). Default: False. script_file (Optional[str]): Script file to execute on database open (-S). Default: None. script_args (List[str]): Arguments to pass to the script (-S). Default: []. file_type (Optional[str]): File type prefix for input (-T). Default: None. file_member (Optional[str]): Archive member name, used with file_type (-T). Default: None. empty_database (bool): If True, creates an empty database (-t). Default: False. windows_dir (Optional[str]): MS Windows directory path (-W). Default: None. no_segmentation (bool): If True, disables segmentation (-x). Default: False. debug_flags (Union\[int, List[str]\]): Debug flags as integer or list of names (-z). Default: 0.

Methods:

- **`build_args`** – Construct the command line arguments string from the configured options.

Attributes:

- **`auto_analysis`** (`bool`) – If False, disables auto analysis (-a). Default: True (enabled).
- **`compiler`** (`Optional[str]`) – Compiler identifier string for the database (-C).
- **`db_compression`** (`Optional[str]`) – Database compression: 'compress', 'pack', or 'no_pack' (-P).
- **`debug_flags`** (`Union[int, List[str]]`) – Debug flags as integer value or list of flag names (-z).
- **`disable_fpp`** (`bool`) – If True, disables FPP instructions (IBM PC only) (-f).
- **`disable_mouse`** (`bool`) – If True, disables mouse support in text mode (-M).
- **`empty_database`** (`bool`) – If True, creates an empty database (-t).
- **`entry_point`** (`Optional[int]`) – Entry point address (-i).
- **`file_member`** (`Optional[str]`) – Archive member name, used with file_type (-T).
- **`file_type`** (`Optional[str]`) – File type prefix for input (-T).
- **`first_pass_directives`** (`List[str]`) – Directives for first pass configuration (-d).
- **`jit_debugger`** (`Optional[bool]`) – If set, enables/disables IDA as just-in-time debugger (-I).
- **`load_resources`** (`bool`) – If True, loads MS Windows exe resources (-R).
- **`loading_address`** (`Optional[int]`) – Address (in paragraphs, 16 bytes each) to load the file at (-b).
- **`log_file`** (`Optional[str]`) – Path to the log file (-L).
- **`new_database`** (`bool`) – If True, deletes the old database and creates a new one (-c).
- **`no_segmentation`** (`bool`) – If True, disables segmentation (-x).
- **`output_database`** (`Optional[str]`) – Output database path (-o). Implies new_database.
- **`plugin_options`** (`Optional[str]`) – Options to pass to plugins (-O).
- **`processor`** (`Optional[str]`) – Processor type identifier (-p).
- **`run_debugger`** (`Optional[str]`) – Debugger options string to run immediately (-r).
- **`script_args`** (`List[str]`) – Arguments to pass to the script file (-S).
- **`script_file`** (`Optional[str]`) – Script file to execute when database opens (-S).
- **`second_pass_directives`** (`List[str]`) – Directives for second pass configuration (-D).
- **`windows_dir`** (`Optional[str]`) – MS Windows directory path (-W).

#### auto_analysis

```
auto_analysis: bool = True

```

If False, disables auto analysis (-a). Default: True (enabled).

#### compiler

```
compiler: Optional[str] = None

```

Compiler identifier string for the database (-C).

#### db_compression

```
db_compression: Optional[str] = None

```

Database compression: 'compress', 'pack', or 'no_pack' (-P).

#### debug_flags

```
debug_flags: Union[int, List[str]] = 0

```

Debug flags as integer value or list of flag names (-z).

#### disable_fpp

```
disable_fpp: bool = False

```

If True, disables FPP instructions (IBM PC only) (-f).

#### disable_mouse

```
disable_mouse: bool = False

```

If True, disables mouse support in text mode (-M).

#### empty_database

```
empty_database: bool = False

```

If True, creates an empty database (-t).

#### entry_point

```
entry_point: Optional[int] = None

```

Entry point address (-i).

#### file_member

```
file_member: Optional[str] = None

```

Archive member name, used with file_type (-T).

#### file_type

```
file_type: Optional[str] = None

```

File type prefix for input (-T).

#### first_pass_directives

```
first_pass_directives: List[str] = field(
    default_factory=list
)

```

Directives for first pass configuration (-d).

#### jit_debugger

```
jit_debugger: Optional[bool] = None

```

If set, enables/disables IDA as just-in-time debugger (-I).

#### load_resources

```
load_resources: bool = False

```

If True, loads MS Windows exe resources (-R).

#### loading_address

```
loading_address: Optional[int] = None

```

Address (in paragraphs, 16 bytes each) to load the file at (-b).

#### log_file

```
log_file: Optional[str] = None

```

Path to the log file (-L).

#### new_database

```
new_database: bool = False

```

If True, deletes the old database and creates a new one (-c).

#### no_segmentation

```
no_segmentation: bool = False

```

If True, disables segmentation (-x).

#### output_database

```
output_database: Optional[str] = None

```

Output database path (-o). Implies new_database.

#### plugin_options

```
plugin_options: Optional[str] = None

```

Options to pass to plugins (-O).

#### processor

```
processor: Optional[str] = None

```

Processor type identifier (-p).

#### run_debugger

```
run_debugger: Optional[str] = None

```

Debugger options string to run immediately (-r).

#### script_args

```
script_args: List[str] = field(default_factory=list)

```

Arguments to pass to the script file (-S).

#### script_file

```
script_file: Optional[str] = None

```

Script file to execute when database opens (-S).

#### second_pass_directives

```
second_pass_directives: List[str] = field(
    default_factory=list
)

```

Directives for second pass configuration (-D).

#### windows_dir

```
windows_dir: Optional[str] = None

```

MS Windows directory path (-W).

#### build_args

```
build_args() -> str

```

Construct the command line arguments string from the configured options.

Returns: str: All command line arguments for IDA, separated by spaces.

# `Entries`

## entries

Classes:

- **`Entries`** – Provides access to entries in the IDA database.
- **`EntryInfo`** – Represents a program entry point.
- **`ForwarderInfo`** – Represents information about an entry point forwarder.

### Entries

```
Entries(database: Database)

```

Bases: `DatabaseEntity`

Provides access to entries in the IDA database.

Can be used to iterate over all entries in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`add`** – Add a new entry point.
- **`exists`** – Check if an entry point with the given ordinal exists.
- **`get_addresses`** – Get all entry point addresses.
- **`get_all`** – Get all entry points.
- **`get_at`** – Get entry point by its address.
- **`get_at_index`** – Get entry point by its index in the entry table.
- **`get_by_name`** – Find entry point by name.
- **`get_by_ordinal`** – Get entry point by its ordinal number.
- **`get_count`** – Get the total number of entry points.
- **`get_forwarders`** – Get all entry points that have forwarders.
- **`get_names`** – Get all entry point names.
- **`get_ordinals`** – Get all ordinal numbers.
- **`rename`** – Rename an existing entry point.
- **`set_forwarder`** – Set forwarder name for an entry point.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### add

```
add(
    address: ea_t,
    name: str,
    ordinal: Optional[int] = None,
    make_code: bool = True,
) -> bool

```

Add a new entry point.

Args: address: Linear address of the entry point name: Name for the entry point ordinal: Ordinal number (if None, uses address as ordinal) make_code: Whether to convert bytes to instructions

Returns: bool: True if successful

#### exists

```
exists(ordinal: int) -> bool

```

Check if an entry point with the given ordinal exists.

Args: ordinal: Ordinal number to check

Returns: bool: True if entry point exists

#### get_addresses

```
get_addresses() -> Iterator[ea_t]

```

Get all entry point addresses.

Yields: int: Each entry point address

#### get_all

```
get_all() -> Iterator[EntryInfo]

```

Get all entry points.

Yields: Entry: Each entry point in the program

#### get_at

```
get_at(ea: ea_t) -> Optional[EntryInfo]

```

Get entry point by its address.

Args: ea: Linear address to search for

Returns: Entry: The entry point at the specified address, or None if not found

#### get_at_index

```
get_at_index(index: int) -> EntryInfo

```

Get entry point by its index in the entry table.

Args: index: Internal index (0 to get_count()-1)

Returns: Entry: The entry point at the specified index

Raises: IndexError: If index is out of range

#### get_by_name

```
get_by_name(name: str) -> Optional[EntryInfo]

```

Find entry point by name.

Args: name: Name to search for

Returns: Entry: The entry point with the specified name, or None if not found

#### get_by_ordinal

```
get_by_ordinal(ordinal: int) -> Optional[EntryInfo]

```

Get entry point by its ordinal number.

Args: ordinal: Ordinal number of the entry point

Returns: Entry: The entry point with the specified ordinal, or None if not found

#### get_count

```
get_count() -> int

```

Get the total number of entry points.

Returns: int: Number of entry points in the program

#### get_forwarders

```
get_forwarders() -> Iterator[ForwarderInfo]

```

Get all entry points that have forwarders.

Yields: ForwarderInfo: Information about each entry with a forwarder

#### get_names

```
get_names() -> Iterator[str]

```

Get all entry point names.

Yields: str: Each entry point name

#### get_ordinals

```
get_ordinals() -> Iterator[int]

```

Get all ordinal numbers.

Yields: int: Each ordinal number

#### rename

```
rename(ordinal: int, new_name: str) -> bool

```

Rename an existing entry point.

Args: ordinal: Ordinal number of the entry point new_name: New name for the entry point

Returns: bool: True if successful

#### set_forwarder

```
set_forwarder(ordinal: int, forwarder_name: str) -> bool

```

Set forwarder name for an entry point.

Args: ordinal: Ordinal number of the entry point forwarder_name: Forwarder name to set

Returns: bool: True if successful

### EntryInfo

```
EntryInfo(
    ordinal: int,
    address: ea_t,
    name: str,
    forwarder_name: str,
)

```

Represents a program entry point. Exported functions are considered entry points as well.

Methods:

- **`has_forwarder`** – Check if this entry point has a forwarder.

Attributes:

- **`address`** (`ea_t`) –
- **`forwarder_name`** (`str`) –
- **`name`** (`str`) –
- **`ordinal`** (`int`) –

#### address

```
address: ea_t

```

#### forwarder_name

```
forwarder_name: str

```

#### name

```
name: str

```

#### ordinal

```
ordinal: int

```

#### has_forwarder

```
has_forwarder() -> bool

```

Check if this entry point has a forwarder.

### ForwarderInfo

```
ForwarderInfo(ordinal: int, name: str)

```

Represents information about an entry point forwarder.

Attributes:

- **`name`** (`str`) –
- **`ordinal`** (`int`) –

#### name

```
name: str

```

#### ordinal

```
ordinal: int

```

# `Flowchart`

## flowchart

Classes:

- **`BasicBlock`** – Provides access to basic block properties and navigation
- **`FlowChart`** – Provides analysis and iteration over basic blocks within
- **`FlowChartFlags`** – Flags for flowchart generation from IDA SDK.

### BasicBlock

```
BasicBlock(
    database: Optional[Database],
    id: int,
    block: qbasic_block_t,
    flowchart: qflow_chart_t,
)

```

Bases: `BasicBlock`, `DatabaseEntity`

Provides access to basic block properties and navigation between connected blocks within a control flow graph.

Initialize basic block.

Args: id: Block ID within the flowchart block: The underlying qbasic_block_t object flowchart: Parent flowchart

Methods:

- **`count_predecessors`** – Count the number of predecessor blocks.
- **`count_successors`** – Count the number of successor blocks.
- **`get_instructions`** – Retrieves all instructions within this basic block.
- **`get_predecessors`** – Iterator over predecessor blocks.
- **`get_successors`** – Iterator over successor blocks.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### count_predecessors

```
count_predecessors() -> int

```

Count the number of predecessor blocks.

#### count_successors

```
count_successors() -> int

```

Count the number of successor blocks.

#### get_instructions

```
get_instructions() -> Optional[Iterator[insn_t]]

```

Retrieves all instructions within this basic block.

Returns: An instruction iterator for this block.

#### get_predecessors

```
get_predecessors() -> Iterator[BasicBlock]

```

Iterator over predecessor blocks.

#### get_successors

```
get_successors() -> Iterator[BasicBlock]

```

Iterator over successor blocks.

### FlowChart

```
FlowChart(
    database: Optional[Database],
    func: func_t = None,
    bounds: Optional[tuple[ea_t, ea_t]] = None,
    flags: FlowChartFlags = NONE,
)

```

Bases: `FlowChart`, `DatabaseEntity`

Provides analysis and iteration over basic blocks within functions or address ranges.

Initialize FlowChart for analyzing basic blocks within functions or address ranges.

Args: database: Database instance to associate with this flowchart. Can be None. func: IDA function object (func_t) to analyze. Defaults to None. bounds: Address range tuple (start_ea, end_ea) defining the analysis scope. Defaults to None. flags: FlowChart creation flags controlling analysis behavior. Defaults to FlowChartFlags.NONE.

Note: At least one of `func` or `bounds` must be specified.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

### FlowChartFlags

Bases: `IntFlag`

Flags for flowchart generation from IDA SDK.

Attributes:

- **`NOEXT`** –
- **`NONE`** –
- **`PREDS`** –

#### NOEXT

```
NOEXT = FC_NOEXT

```

#### NONE

```
NONE = 0

```

#### PREDS

```
PREDS = FC_PREDS

```

# `Functions`

## functions

Classes:

- **`FunctionChunk`** – Represents a function chunk (main or tail).
- **`FunctionFlags`** – Function attribute flags from IDA SDK.
- **`Functions`** – Provides access to function-related operations within the IDA database.
- **`LocalVariable`** – Represents a local variable or argument in a function.
- **`LocalVariableAccessType`** – Type of access to a local variable.
- **`LocalVariableContext`** – Context where local variable is referenced.
- **`LocalVariableReference`** – Reference to a local variable in pseudocode.
- **`StackPoint`** – Stack pointer change information.
- **`TailInfo`** – Function tail chunk information.

### FunctionChunk

```
FunctionChunk(start_ea: ea_t, end_ea: ea_t, is_main: bool)

```

Represents a function chunk (main or tail).

Attributes:

- **`end_ea`** (`ea_t`) – End address of the function chunk
- **`is_main`** (`bool`) – True if is the function main chunk
- **`start_ea`** (`ea_t`) – Start address of the function chunk

#### end_ea

```
end_ea: ea_t

```

End address of the function chunk

#### is_main

```
is_main: bool

```

True if is the function main chunk

#### start_ea

```
start_ea: ea_t

```

Start address of the function chunk

### FunctionFlags

Bases: `Flag`

Function attribute flags from IDA SDK.

Attributes:

- **`BOTTOMBP`** – BP points to the bottom of the stack frame
- **`CATCH`** – Function is an exception catch handler
- **`FAR`** – Far function
- **`FRAME`** – Function uses frame pointer (BP)
- **`FUZZY_SP`** – Function changes SP in untraceable way
- **`HIDDEN`** – A hidden function chunk
- **`LIB`** – Library function
- **`LUMINA`** – Function info is provided by Lumina
- **`NORET`** – Function doesn't return
- **`NORET_PENDING`** – Function 'non-return' analysis needed
- **`OUTLINE`** – Outlined code, not a real function
- **`PROLOG_OK`** – Prolog analysis has been performed
- **`PURGED_OK`** – 'argsize' field has been validated
- **`REANALYZE`** – Function frame changed, request to reanalyze
- **`SP_READY`** – SP-analysis has been performed
- **`STATICDEF`** – Static function
- **`TAIL`** – This is a function tail
- **`THUNK`** – Thunk (jump) function
- **`UNWIND`** – Function is an exception unwind handler
- **`USERFAR`** – User has specified far-ness of the function

#### BOTTOMBP

```
BOTTOMBP = FUNC_BOTTOMBP

```

BP points to the bottom of the stack frame

#### CATCH

```
CATCH = FUNC_CATCH

```

Function is an exception catch handler

#### FAR

```
FAR = FUNC_FAR

```

Far function

#### FRAME

```
FRAME = FUNC_FRAME

```

Function uses frame pointer (BP)

#### FUZZY_SP

```
FUZZY_SP = FUNC_FUZZY_SP

```

Function changes SP in untraceable way

#### HIDDEN

```
HIDDEN = FUNC_HIDDEN

```

A hidden function chunk

#### LIB

```
LIB = FUNC_LIB

```

Library function

#### LUMINA

```
LUMINA = FUNC_LUMINA

```

Function info is provided by Lumina

#### NORET

```
NORET = FUNC_NORET

```

Function doesn't return

#### NORET_PENDING

```
NORET_PENDING = FUNC_NORET_PENDING

```

Function 'non-return' analysis needed

#### OUTLINE

```
OUTLINE = FUNC_OUTLINE

```

Outlined code, not a real function

#### PROLOG_OK

```
PROLOG_OK = FUNC_PROLOG_OK

```

Prolog analysis has been performed

#### PURGED_OK

```
PURGED_OK = FUNC_PURGED_OK

```

'argsize' field has been validated

#### REANALYZE

```
REANALYZE = FUNC_REANALYZE

```

Function frame changed, request to reanalyze

#### SP_READY

```
SP_READY = FUNC_SP_READY

```

SP-analysis has been performed

#### STATICDEF

```
STATICDEF = FUNC_STATICDEF

```

Static function

#### TAIL

```
TAIL = FUNC_TAIL

```

This is a function tail

#### THUNK

```
THUNK = FUNC_THUNK

```

Thunk (jump) function

#### UNWIND

```
UNWIND = FUNC_UNWIND

```

Function is an exception unwind handler

#### USERFAR

```
USERFAR = FUNC_USERFAR

```

User has specified far-ness of the function

### Functions

```
Functions(database: Database)

```

Bases: `DatabaseEntity`

Provides access to function-related operations within the IDA database.

This class handles function discovery, analysis, manipulation, and provides access to function properties like names, signatures, basic blocks, and pseudocode.

Can be used to iterate over all functions in the opened database.

Args: database: Reference to the active IDA database.

Note: Since this class does not manage the lifetime of IDA kernel objects (func_t\*), it is recommended to use these pointers within a limited scope. Obtain the pointer, perform the necessary operations, and avoid retaining references beyond the immediate context to prevent potential issues with object invalidation.

Methods:

- **`create`** – Creates a new function at the specified address.
- **`does_return`** – Check if function returns.
- **`get_all`** – Retrieves all functions in the database.
- **`get_at`** – Retrieves the function that contains the given address.
- **`get_between`** – Retrieves functions within the specified address range.
- **`get_callees`** – Gets all functions called by this function.
- **`get_callers`** – Gets all functions that call this function.
- **`get_chunk_at`** – Get function chunk at exact address.
- **`get_chunks`** – Get all chunks (main and tail) of a function.
- **`get_comment`** – Get comment for function.
- **`get_data_items`** – Iterate over data items within the function.
- **`get_disassembly`** – Retrieves the disassembly lines for the given function.
- **`get_flags`** – Get function attribute flags.
- **`get_flowchart`** – Retrieves the flowchart of the specified function,
- **`get_function_by_name`** – Find a function by its name.
- **`get_instructions`** – Retrieves all instructions within the given function.
- **`get_local_variable_by_name`** – Find a local variable by name.
- **`get_local_variable_references`** – Get all references to a specific local variable.
- **`get_local_variables`** – Get all local variables for a function.
- **`get_microcode`** – Retrieves the microcode of the given function.
- **`get_name`** – Retrieves the function's name.
- **`get_next`** – Get the next function after the given address.
- **`get_pseudocode`** – Retrieves the decompiled pseudocode of the given function.
- **`get_signature`** – Retrieves the function's type signature.
- **`get_stack_points`** – Get function stack points for SP tracking.
- **`get_tail_info`** – Get information about tail chunk's owner function.
- **`get_tails`** – Get all tail chunks of a function.
- **`is_chunk_at`** – Check if the given address belongs to a function chunk.
- **`is_entry_chunk`** – Check if chunk is entry chunk.
- **`is_far`** – Check if function is far.
- **`is_tail_chunk`** – Check if chunk is tail chunk.
- **`remove`** – Removes the function at the specified address.
- **`set_comment`** – Set comment for function.
- **`set_name`** – Renames the given function.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### create

```
create(ea: ea_t) -> bool

```

Creates a new function at the specified address.

Args: ea: The effective address where the function should start.

Returns: True if the function was successfully created, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### does_return

```
does_return(func: func_t) -> bool

```

Check if function returns.

Args: func: Function object

Returns: True if function returns, False if it's noreturn

#### get_all

```
get_all() -> Iterator[func_t]

```

Retrieves all functions in the database.

Returns: An iterator over all functions in the database.

#### get_at

```
get_at(ea: ea_t) -> Optional[func_t]

```

Retrieves the function that contains the given address.

Args: ea: An effective address within the function body.

Returns: The function object containing the address, or None if no function exists at that address.

Raises: InvalidEAError: If the effective address is invalid.

#### get_between

```
get_between(
    start_ea: ea_t, end_ea: ea_t
) -> Iterator[func_t]

```

Retrieves functions within the specified address range.

Args: start_ea: Start address of the range (inclusive). end_ea: End address of the range (exclusive).

Yields: Function objects whose start address falls within the specified range.

Raises: InvalidEAError: If the start_ea/end_ea are specified but they are not in the database range.

#### get_callees

```
get_callees(func: func_t) -> List[func_t]

```

Gets all functions called by this function.

Args: func: The function instance.

Returns: List of called functions.

#### get_callers

```
get_callers(func: func_t) -> List[func_t]

```

Gets all functions that call this function.

Args: func: The function instance.

Returns: List of calling functions.

#### get_chunk_at

```
get_chunk_at(ea: int) -> Optional[func_t]

```

Get function chunk at exact address.

Args: ea: Address within function chunk

Returns: Function chunk or None

Raises: InvalidEAError: If the effective address is invalid.

#### get_chunks

```
get_chunks(func: func_t) -> Iterator[FunctionChunk]

```

Get all chunks (main and tail) of a function.

Args: func: The function to analyze.

Yields: FunctionChunk objects representing each chunk.

#### get_comment

```
get_comment(func: func_t, repeatable: bool = False) -> str

```

Get comment for function.

Args: func: The function to get comment from. repeatable: If True, retrieves repeatable comment (shows at all identical operands). If False, retrieves non-repeatable comment (shows only at this function).

Returns: Comment text, or empty string if no comment exists.

#### get_data_items

```
get_data_items(func: func_t) -> Iterator[ea_t]

```

Iterate over data items within the function.

This method finds all addresses within the function that are defined as data (not code). Useful for finding embedded data, jump tables, or other non-code items within function boundaries.

Args: func: The function object

Yields: Addresses of data items within the function

Example:

```
>>> func = db.functions.get_at(0x401000)
>>> for data_ea in db.functions.get_data_items(func):
...     size = ida_bytes.get_item_size(data_ea)
...     print(f"Data at 0x{data_ea:x}, size: {size}")

```

#### get_disassembly

```
get_disassembly(
    func: func_t, remove_tags: bool = True
) -> List[str]

```

Retrieves the disassembly lines for the given function.

Args: func: The function instance. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: A list of strings, each representing a line of disassembly. Returns empty list if function is invalid.

#### get_flags

```
get_flags(func: func_t) -> FunctionFlags

```

Get function attribute flags.

Args: func: Function object

Returns: FunctionFlags enum with all active flags

#### get_flowchart

```
get_flowchart(
    func: func_t, flags: FlowChartFlags = NONE
) -> Optional[FlowChart]

```

Retrieves the flowchart of the specified function, which the user can use to retrieve basic blocks.

Args: func: The function instance.

Returns: An iterator over the function's basic blocks, or empty iterator if function is invalid.

#### get_function_by_name

```
get_function_by_name(name: str) -> Optional[func_t]

```

Find a function by its name.

Args: name: Function name to search for

Returns: Function object if found, None otherwise

#### get_instructions

```
get_instructions(
    func: func_t,
) -> Optional[Iterator[insn_t]]

```

Retrieves all instructions within the given function.

Args: func: The function instance.

Returns: An iterator over all instructions in the function, or empty iterator if function is invalid.

#### get_local_variable_by_name

```
get_local_variable_by_name(
    func: func_t, name: str
) -> Optional[LocalVariable]

```

Find a local variable by name.

Args: func: The function instance. name: Variable name to search for.

Returns: LocalVariable if found

Raises: RuntimeError: If decompilation fails for the function. KeyError: If the variable is not found

#### get_local_variable_references

```
get_local_variable_references(
    func: func_t, lvar: LocalVariable
) -> List[LocalVariableReference]

```

Get all references to a specific local variable.

Args: func: The function instance. lvar: The local variable to find references for.

Returns: List of references to the variable in pseudocode.

Raises: RuntimeError: If decompilation fails for the function.

#### get_local_variables

```
get_local_variables(func: func_t) -> List[LocalVariable]

```

Get all local variables for a function.

Args: func: The function instance.

Returns: List of local variables including arguments and local vars.

Raises: RuntimeError: If decompilation fails for the function.

#### get_microcode

```
get_microcode(
    func: func_t, remove_tags: bool = True
) -> List[str]

```

Retrieves the microcode of the given function.

Args: func: The function instance. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: A list of strings, each representing a line of microcode. Returns empty list if function is invalid or decompilation fails.

Raises: RuntimeError: If microcode generation fails for the function.

#### get_name

```
get_name(func: func_t) -> str

```

Retrieves the function's name.

Args: func: The function instance.

Returns: The function name as a string, or empty string if no name is set.

#### get_next

```
get_next(ea: int) -> Optional[func_t]

```

Get the next function after the given address.

Args: ea: Address to search from

Returns: Next function after ea, or None if no more functions

Raises: InvalidEAError: If the effective address is invalid.

#### get_pseudocode

```
get_pseudocode(
    func: func_t, remove_tags: bool = True
) -> List[str]

```

Retrieves the decompiled pseudocode of the given function.

Args: func: The function instance. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: A list of strings, each representing a line of pseudocode. Returns empty list if function is invalid or decompilation fails.

Raises: RuntimeError: If decompilation fails for the function.

#### get_signature

```
get_signature(func: func_t) -> str

```

Retrieves the function's type signature.

Args: func: The function instance.

Returns: The function signature as a string, or empty string if unavailable or function is invalid.

#### get_stack_points

```
get_stack_points(func: func_t) -> List[StackPoint]

```

Get function stack points for SP tracking.

Args: func: Function object

Returns: List of StackPoint objects showing where SP changes

#### get_tail_info

```
get_tail_info(chunk: func_t) -> Optional[TailInfo]

```

Get information about tail chunk's owner function.

Args: chunk: Function chunk (must be tail chunk)

Returns: TailInfo with owner details, or None if not a tail chunk

#### get_tails

```
get_tails(func: func_t) -> List[func_t]

```

Get all tail chunks of a function.

Args: func: Function object (must be entry chunk)

Returns: List of tail chunks, empty if not entry chunk

#### is_chunk_at

```
is_chunk_at(ea: ea_t) -> bool

```

Check if the given address belongs to a function chunk.

Args: ea: The address to check.

Returns: True if the address is in a function chunk.

#### is_entry_chunk

```
is_entry_chunk(chunk: func_t) -> bool

```

Check if chunk is entry chunk.

Args: chunk: Function chunk to check

Returns: True if this is an entry chunk, False otherwise

#### is_far

```
is_far(func: func_t) -> bool

```

Check if function is far.

Args: func: Function object

Returns: True if function is far, False otherwise

#### is_tail_chunk

```
is_tail_chunk(chunk: func_t) -> bool

```

Check if chunk is tail chunk.

Args: chunk: Function chunk to check

Returns: True if this is a tail chunk, False otherwise

#### remove

```
remove(ea: ea_t) -> bool

```

Removes the function at the specified address.

Args: ea: The effective address of the function to remove.

Returns: True if the function was successfully removed, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### set_comment

```
set_comment(
    func: func_t, comment: str, repeatable: bool = False
) -> bool

```

Set comment for function.

Args: func: The function to set comment for. comment: Comment text to set. repeatable: If True, creates a repeatable comment (shows at all identical operands). If False, creates a non-repeatable comment (shows only at this function).

Returns: True if successful, False otherwise.

#### set_name

```
set_name(
    func: func_t, name: str, auto_correct: bool = True
) -> bool

```

Renames the given function.

Args: func: The function instance. name: The new name to assign to the function. auto_correct: If True, allows IDA to replace invalid characters automatically.

Returns: True if the function was successfully renamed, False otherwise.

Raises: InvalidParameterError: If the name parameter is empty or invalid.

### LocalVariable

```
LocalVariable(
    index: int,
    name: str,
    type: Optional[tinfo_t],
    size: int,
    is_argument: bool,
    is_result: bool,
)

```

Represents a local variable or argument in a function.

Attributes:

- **`index`** (`int`) – Variable index in function
- **`is_argument`** (`bool`) – True if is a function argument
- **`is_result`** (`bool`) – True if is a return value variable
- **`name`** (`str`) – Variable name
- **`size`** (`int`) – Size in bytes
- **`type`** (`Optional[tinfo_t]`) – Type information
- **`type_str`** (`str`) – Get string representation of the type.

#### index

```
index: int

```

Variable index in function

#### is_argument

```
is_argument: bool

```

True if is a function argument

#### is_result

```
is_result: bool

```

True if is a return value variable

#### name

```
name: str

```

Variable name

#### size

```
size: int

```

Size in bytes

#### type

```
type: Optional[tinfo_t]

```

Type information

#### type_str

```
type_str: str

```

Get string representation of the type.

### LocalVariableAccessType

Bases: `IntEnum`

Type of access to a local variable.

Attributes:

- **`ADDRESS`** – Address of variable is taken (&var)
- **`READ`** – Variable value is read
- **`WRITE`** – Variable value is modified

#### ADDRESS

```
ADDRESS = 3

```

Address of variable is taken (&var)

#### READ

```
READ = 1

```

Variable value is read

#### WRITE

```
WRITE = 2

```

Variable value is modified

### LocalVariableContext

Bases: `Enum`

Context where local variable is referenced.

Attributes:

- **`ARITHMETIC`** – var + 1, var * 2, etc.
- **`ARRAY_INDEX`** – arr[var] or var[i]
- **`ASSIGNMENT`** – var = expr or expr = var
- **`CALL_ARG`** – func(var)
- **`CAST`** – (type)var
- **`COMPARISON`** – var == x, var < y, etc.
- **`CONDITION`** – if (var), while (var), etc.
- **`OTHER`** – Other contexts
- **`POINTER_DEREF`** – \*var or var->field
- **`RETURN`** – return var

#### ARITHMETIC

```
ARITHMETIC = 'arithmetic'

```

var + 1, var * 2, etc.

#### ARRAY_INDEX

```
ARRAY_INDEX = 'array_index'

```

arr[var] or var[i]

#### ASSIGNMENT

```
ASSIGNMENT = 'assignment'

```

var = expr or expr = var

#### CALL_ARG

```
CALL_ARG = 'call_arg'

```

func(var)

#### CAST

```
CAST = 'cast'

```

(type)var

#### COMPARISON

```
COMPARISON = 'comparison'

```

var == x, var < y, etc.

#### CONDITION

```
CONDITION = 'condition'

```

if (var), while (var), etc.

#### OTHER

```
OTHER = 'other'

```

Other contexts

#### POINTER_DEREF

```
POINTER_DEREF = 'pointer_deref'

```

\*var or var->field

#### RETURN

```
RETURN = 'return'

```

return var

### LocalVariableReference

```
LocalVariableReference(
    access_type: LocalVariableAccessType,
    context: Optional[LocalVariableContext] = None,
    ea: Optional[ea_t] = None,
    line_number: Optional[int] = None,
    code_line: Optional[str] = None,
)

```

Reference to a local variable in pseudocode.

Attributes:

- **`access_type`** (`LocalVariableAccessType`) – How variable is accessed
- **`code_line`** (`Optional[str]`) – The pseudocode line containing the reference
- **`context`** (`Optional[LocalVariableContext]`) – Usage context
- **`ea`** (`Optional[ea_t]`) – Binary address if mappable
- **`line_number`** (`Optional[int]`) – Line number in pseudocode

#### access_type

```
access_type: LocalVariableAccessType

```

How variable is accessed

#### code_line

```
code_line: Optional[str] = None

```

The pseudocode line containing the reference

#### context

```
context: Optional[LocalVariableContext] = None

```

Usage context

#### ea

```
ea: Optional[ea_t] = None

```

Binary address if mappable

#### line_number

```
line_number: Optional[int] = None

```

Line number in pseudocode

### StackPoint

```
StackPoint(ea: ea_t, sp_delta: int)

```

Stack pointer change information.

Attributes:

- **`ea`** (`ea_t`) – Address where SP changes
- **`sp_delta`** (`int`) – Stack pointer delta at this point

#### ea

```
ea: ea_t

```

Address where SP changes

#### sp_delta

```
sp_delta: int

```

Stack pointer delta at this point

### TailInfo

```
TailInfo(owner_ea: ea_t, owner_name: str)

```

Function tail chunk information.

Attributes:

- **`owner_ea`** (`ea_t`) – Address of owning function
- **`owner_name`** (`str`) – Name of owning function

#### owner_ea

```
owner_ea: ea_t

```

Address of owning function

#### owner_name

```
owner_name: str

```

Name of owning function

# `Heads`

## heads

Classes:

- **`Heads`** – Provides access to heads (instructions or data items) in the IDA database.

### Heads

```
Heads(database: Database)

```

Bases: `DatabaseEntity`

Provides access to heads (instructions or data items) in the IDA database.

Can be used to iterate over all heads in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`bounds`** – Get the bounds (start and end addresses) of the item containing the given address.
- **`get_all`** – Retrieves an iterator over all heads in the database.
- **`get_between`** – Retrieves all basic heads between two addresses.
- **`get_next`** – Get the next head address.
- **`get_previous`** – Get the previous head address.
- **`is_code`** – Check if the item at the given address is code.
- **`is_data`** – Check if the item at the given address is data.
- **`is_head`** – Check if the given address is a head (start of an item).
- **`is_tail`** – Check if the given address is a tail (part of an item but not the start).
- **`is_unknown`** – Check if the item at the given address is unknown.
- **`size`** – Get the size of the item at the given address.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### bounds

```
bounds(ea: ea_t) -> tuple[ea_t, ea_t]

```

Get the bounds (start and end addresses) of the item containing the given address.

Args: ea: Address within the item.

Returns: Tuple of (start_address, end_address) of the item.

Raises: InvalidEAError: If the effective address is not in the database range.

#### get_all

```
get_all() -> Iterator[ea_t]

```

Retrieves an iterator over all heads in the database.

Returns: An iterator over the heads.

#### get_between

```
get_between(start_ea: ea_t, end_ea: ea_t) -> Iterator[ea_t]

```

Retrieves all basic heads between two addresses.

Args: start_ea: Start address of the range. end_ea: End address of the range.

Returns: An iterator over the heads.

Raises: InvalidEAError: If the effective address is not in the database range.

#### get_next

```
get_next(ea: ea_t) -> Optional[ea_t]

```

Get the next head address.

Args: ea: Current address.

Returns: Next head address, or None if no next head exists.

Raises: InvalidEAError: If the effective address is not in the database range.

#### get_previous

```
get_previous(ea: ea_t) -> Optional[ea_t]

```

Get the previous head address.

Args: ea: Current address.

Returns: Previous head address, or None if no previous head exists.

Raises: InvalidEAError: If the effective address is not in the database range.

#### is_code

```
is_code(ea: ea_t) -> bool

```

Check if the item at the given address is code.

Args: ea: Address to check.

Returns: True if the item is code, False otherwise.

Raises: InvalidEAError: If the effective address is not in the database range.

#### is_data

```
is_data(ea: ea_t) -> bool

```

Check if the item at the given address is data.

Args: ea: Address to check.

Returns: True if the item is data, False otherwise.

Raises: InvalidEAError: If the effective address is not in the database range.

#### is_head

```
is_head(ea: ea_t) -> bool

```

Check if the given address is a head (start of an item).

Args: ea: Address to check.

Returns: True if the address is a head, False otherwise.

Raises: InvalidEAError: If the effective address is not in the database range.

#### is_tail

```
is_tail(ea: ea_t) -> bool

```

Check if the given address is a tail (part of an item but not the start).

Args: ea: Address to check.

Returns: True if the address is a tail, False otherwise.

Raises: InvalidEAError: If the effective address is not in the database range.

#### is_unknown

```
is_unknown(ea: ea_t) -> bool

```

Check if the item at the given address is unknown.

Args: ea: Address to check.

Returns: True if the item is data, False otherwise.

Raises: InvalidEAError: If the effective address is not in the database range.

#### size

```
size(ea: ea_t) -> int

```

Get the size of the item at the given address.

Args: ea: Address of the item.

Returns: Size of the item in bytes.

Raises: InvalidEAError: If the effective address is not in the database range. InvalidParameterError: If the address is not a head.

# `Hooks`

## hooks

Classes:

- **`DatabaseHooks`** – Convenience class for IDB (database) events handling.
- **`DebuggerHooks`** – Convenience class for debugger events handling.
- **`DecompilerHooks`** – Convenience class for decompiler events handling.
- **`ProcessorHooks`** – Convenience class for IDP (processor) events handling.
- **`UIHooks`** – Convenience class for UI events handling.
- **`ViewHooks`** – Convenience class for IDA View events handling.

Attributes:

- **`HooksList`** (`TypeAlias`) –

### HooksList

```
HooksList: TypeAlias = list[
    Union[
        ProcessorHooks,
        DatabaseHooks,
        DebuggerHooks,
        DecompilerHooks,
        UIHooks,
        ViewHooks,
    ]
]

```

### DatabaseHooks

```
DatabaseHooks()

```

Bases: `_BaseHooks`, `IDB_Hooks`

Convenience class for IDB (database) events handling.

Methods:

- **`adding_segm`** – A segment is being created.
- **`allsegs_moved`** – Program rebasing is complete. This event is generated after a series of segm_moved events.
- **`auto_empty`** – Info: all analysis queues are empty. This callback is called once when the initial
- **`auto_empty_finally`** – Info: all analysis queues are empty definitively. This callback is called only once.
- **`bookmark_changed`** – Bookmarked position changed.
- **`byte_patched`** – A byte has been patched.
- **`callee_addr_changed`** – Callee address has been updated by the user.
- **`changing_cmt`** – An item comment is to be changed.
- **`changing_op_ti`** – An operand typestring (c/c++ prototype) is to be changed.
- **`changing_op_type`** – An operand type (offset, hex, etc...) is to be changed.
- **`changing_range_cmt`** – Range comment is to be changed.
- **`changing_segm_class`** – Segment class is being changed.
- **`changing_segm_end`** – Segment end address is to be changed.
- **`changing_segm_name`** – Segment name is being changed.
- **`changing_segm_start`** – Segment start address is to be changed.
- **`changing_ti`** – An item typestring (c/c++ prototype) is to be changed.
- **`closebase`** – The database will be closed now.
- **`cmt_changed`** – An item comment has been changed.
- **`compiler_changed`** – The kernel has changed the compiler information (idainfo::cc structure; get_abi_name).
- **`deleting_func`** – The kernel is about to delete a function.
- **`deleting_func_tail`** – A function tail chunk is to be removed.
- **`deleting_segm`** – A segment is to be deleted.
- **`deleting_tryblks`** – About to delete tryblk information in given range.
- **`destroyed_items`** – Instructions/data have been destroyed in \[ea1, ea2).
- **`determined_main`** – The main() function has been determined.
- **`dirtree_link`** – Dirtree: an item has been linked/unlinked.
- **`dirtree_mkdir`** – Dirtree: a directory has been created.
- **`dirtree_move`** – Dirtree: a directory or item has been moved.
- **`dirtree_rank`** – Dirtree: a directory or item rank has been changed.
- **`dirtree_rmdir`** – Dirtree: a directory has been deleted.
- **`dirtree_rminode`** – Dirtree: an inode became unavailable.
- **`dirtree_segm_moved`** – Dirtree: inodes were changed due to a segment movement or a program rebasing.
- **`extlang_changed`** – The list of extlangs or the default extlang was changed.
- **`extra_cmt_changed`** – An extra comment has been changed.
- **`flow_chart_created`** – GUI has retrieved a function flow chart.
- **`frame_created`** – A function frame has been created.
- **`frame_deleted`** – The kernel has deleted a function frame.
- **`frame_expanded`** – A frame type has been expanded or shrunk.
- **`frame_udm_changed`** – Frame member has been changed.
- **`frame_udm_created`** – Frame member has been added.
- **`frame_udm_deleted`** – Frame member has been deleted.
- **`frame_udm_renamed`** – Frame member has been renamed.
- **`func_added`** – The kernel has added a function.
- **`func_deleted`** – A function has been deleted.
- **`func_noret_changed`** – FUNC_NORET bit has been changed.
- **`func_tail_appended`** – A function tail chunk has been appended.
- **`func_tail_deleted`** – A function tail chunk has been removed.
- **`func_updated`** – The kernel has updated a function.
- **`hook`** – Hook (activate) the event handlers.
- **`idasgn_loaded`** – FLIRT signature has been loaded for normal processing
- **`idasgn_matched_ea`** – A FLIRT match has been found.
- **`item_color_changed`** – An item color has been changed.
- **`kernel_config_loaded`** – This event is issued when ida.cfg is parsed.
- **`loader_finished`** – External file loader finished its work.
- **`local_type_renamed`** – Local type has been renamed.
- **`local_types_changed`** – Local types have been changed.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`lt_edm_changed`** – Local type enum member has been changed.
- **`lt_edm_created`** – Local type enum member has been added.
- **`lt_edm_deleted`** – Local type enum member has been deleted.
- **`lt_edm_renamed`** – Local type enum member has been renamed.
- **`lt_udm_changed`** – Local type UDT member has been changed.
- **`lt_udm_created`** – Local type UDT member has been added.
- **`lt_udm_deleted`** – Local type UDT member has been deleted.
- **`lt_udm_renamed`** – Local type UDT member has been renamed.
- **`lt_udt_expanded`** – A structure type has been expanded or shrunk.
- **`make_code`** – An instruction is being created.
- **`make_data`** – A data item is being created.
- **`op_ti_changed`** – An operand typestring (c/c++ prototype) has been changed.
- **`op_type_changed`** – An operand type (offset, hex, etc...) has been set or deleted.
- **`range_cmt_changed`** – Range comment has been changed.
- **`renamed`** – The kernel has renamed a byte. See also the rename event.
- **`savebase`** – The database is being saved.
- **`segm_added`** – A new segment has been created.
- **`segm_attrs_updated`** – Segment attributes have been changed.
- **`segm_class_changed`** – Segment class has been changed.
- **`segm_deleted`** – A segment has been deleted.
- **`segm_end_changed`** – Segment end address has been changed.
- **`segm_moved`** – Segment has been moved.
- **`segm_name_changed`** – Segment name has been changed.
- **`segm_start_changed`** – Segment start address has been changed.
- **`set_func_end`** – Function chunk end address will be changed.
- **`set_func_start`** – Function chunk start address will be changed.
- **`sgr_changed`** – The kernel has changed a segment register value.
- **`sgr_deleted`** – The kernel has deleted a segment register value.
- **`stkpnts_changed`** – Stack change points have been modified.
- **`tail_owner_changed`** – A tail chunk owner has been changed.
- **`thunk_func_created`** – A thunk bit has been set for a function.
- **`ti_changed`** – An item typestring (c/c++ prototype) has been changed.
- **`tryblks_updated`** – Updated tryblk information.
- **`unhook`** – Un-hook (de-activate) the event handlers.
- **`updating_tryblks`** – About to update tryblk information.
- **`upgraded`** – The database has been upgraded and the receiver can upgrade its info as well.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### adding_segm

```
adding_segm(s: 'segment_t *') -> None

```

A segment is being created.

Args: s (segment_t): The segment being created.

#### allsegs_moved

```
allsegs_moved(info: 'segm_move_infos_t *') -> None

```

Program rebasing is complete. This event is generated after a series of segm_moved events.

Args: info (segm_move_infos_t \*): Information about all moved segments.

#### auto_empty

```
auto_empty() -> None

```

Info: all analysis queues are empty. This callback is called once when the initial analysis is finished. If the queue is not empty upon the return from this callback, it will be called later again.

#### auto_empty_finally

```
auto_empty_finally() -> None

```

Info: all analysis queues are empty definitively. This callback is called only once.

#### bookmark_changed

```
bookmark_changed(
    index: int,
    pos: 'lochist_entry_t const *',
    desc: str,
    operation: int,
) -> None

```

Bookmarked position changed.

Args: index (int): Bookmark index (uint32). pos (lochist_entry_t): Position info. desc (str): Description, or None if deleted. operation (int): 0 = added, 1 = updated, 2 = deleted. If desc is None, the bookmark was deleted.

#### byte_patched

```
byte_patched(ea: ea_t, old_value: int) -> None

```

A byte has been patched.

Args: ea (ea_t): Address of the patched byte. old_value (int): Previous value (uint32).

#### callee_addr_changed

```
callee_addr_changed(ea: ea_t, callee: ea_t) -> None

```

Callee address has been updated by the user.

Args: ea (ea_t): Address of the call instruction. callee (ea_t): Updated callee address.

#### changing_cmt

```
changing_cmt(
    ea: ea_t, repeatable_cmt: bool, newcmt: str
) -> None

```

An item comment is to be changed.

Args: ea (ea_t): Address of the item. repeatable_cmt (bool): True if the comment is repeatable. newcmt (str): New comment text.

#### changing_op_ti

```
changing_op_ti(
    ea: ea_t,
    n: int,
    new_type: 'type_t const *',
    new_fnames: 'p_list const *',
) -> None

```

An operand typestring (c/c++ prototype) is to be changed.

Args: ea (ea_t): Address. n (int): Operand number. new_type (type_t const *): New type. new_fnames (p_list const* ): New field names.

#### changing_op_type

```
changing_op_type(
    ea: ea_t, n: int, opinfo: opinfo_t
) -> None

```

An operand type (offset, hex, etc...) is to be changed.

Args: ea (ea_t): Address. n (int): Operand number (eventually or'ed with OPND_OUTER or OPND_ALL). opinfo (opinfo_t): Additional operand info.

#### changing_range_cmt

```
changing_range_cmt(
    kind: range_kind_t,
    a: range_t,
    cmt: str,
    repeatable: bool,
) -> None

```

Range comment is to be changed.

Args: kind (range_kind_t): Kind of the range. a (range_t): The range. cmt (str): New comment text. repeatable (bool): True if the comment is repeatable.

#### changing_segm_class

```
changing_segm_class(s: 'segment_t *') -> None

```

Segment class is being changed.

Args: s (segment_t \*): The segment whose class is changing.

#### changing_segm_end

```
changing_segm_end(
    s: 'segment_t *', new_end: ea_t, segmod_flags: int
) -> None

```

Segment end address is to be changed.

Args: s (segment_t \*): The segment. new_end (ea_t): New end address. segmod_flags (int): Segment modification flags.

#### changing_segm_name

```
changing_segm_name(s: 'segment_t *', oldname: str) -> None

```

Segment name is being changed.

Args: s (segment_t \*): The segment whose name is changing. oldname (str): The old segment name.

#### changing_segm_start

```
changing_segm_start(
    s: 'segment_t *', new_start: ea_t, segmod_flags: int
) -> None

```

Segment start address is to be changed.

Args: s (segment_t \*): The segment. new_start (ea_t): New start address. segmod_flags (int): Segment modification flags.

#### changing_ti

```
changing_ti(
    ea: ea_t,
    new_type: 'type_t const *',
    new_fnames: 'p_list const *',
) -> None

```

An item typestring (c/c++ prototype) is to be changed.

Args: ea (ea_t): Address. new_type (type_t const *): New type. new_fnames (p_list const* ): New field names.

#### closebase

```
closebase() -> None

```

The database will be closed now.

#### cmt_changed

```
cmt_changed(ea: ea_t, repeatable_cmt: bool) -> None

```

An item comment has been changed.

Args: ea (ea_t): Address of the item. repeatable_cmt (bool): True if the comment is repeatable.

#### compiler_changed

```
compiler_changed(adjust_inf_fields: bool) -> None

```

The kernel has changed the compiler information (idainfo::cc structure; get_abi_name).

Args: adjust_inf_fields (bool): May change inf fields.

#### deleting_func

```
deleting_func(pfn: 'func_t *') -> None

```

The kernel is about to delete a function.

Args: pfn (func_t \*): The function that will be deleted.

#### deleting_func_tail

```
deleting_func_tail(pfn: 'func_t *', tail: range_t) -> None

```

A function tail chunk is to be removed.

Args: pfn (func_t \*): The function from which the tail will be removed. tail (range_t): The tail range to be removed.

#### deleting_segm

```
deleting_segm(start_ea: ea_t) -> None

```

A segment is to be deleted.

Args: start_ea (ea_t): Start address of the segment to delete.

#### deleting_tryblks

```
deleting_tryblks(range: range_t) -> None

```

About to delete tryblk information in given range.

Args: range (range_t): The range from which try blocks will be deleted.

#### destroyed_items

```
destroyed_items(
    ea1: ea_t, ea2: ea_t, will_disable_range: bool
) -> None

```

Instructions/data have been destroyed in \[ea1, ea2).

Args: ea1 (ea_t): Start address of destroyed range. ea2 (ea_t): End address of destroyed range. will_disable_range (bool): True if the range will be disabled.

#### determined_main

```
determined_main(main: ea_t) -> None

```

The main() function has been determined.

Args: main (ea_t): Address of the main() function.

#### dirtree_link

```
dirtree_link(
    dt: 'dirtree_t *', path: str, link: bool
) -> None

```

Dirtree: an item has been linked/unlinked.

Args: dt (dirtree_t): The dirtree object. path (str): Path of the item. link (bool): True if linked, False if unlinked.

#### dirtree_mkdir

```
dirtree_mkdir(dt: 'dirtree_t *', path: str) -> None

```

Dirtree: a directory has been created.

Args: dt (dirtree_t): The dirtree object. path (str): Path to the created directory.

#### dirtree_move

```
dirtree_move(
    dt: 'dirtree_t *', _from: str, to: str
) -> None

```

Dirtree: a directory or item has been moved.

Args: dt (dirtree_t): The dirtree object. \_from (str): Source path. to (str): Destination path.

#### dirtree_rank

```
dirtree_rank(
    dt: 'dirtree_t *', path: str, rank: size_t
) -> None

```

Dirtree: a directory or item rank has been changed.

Args: dt (dirtree_t): The dirtree object. path (str): Path of the directory or item. rank (size_t): New rank value.

#### dirtree_rmdir

```
dirtree_rmdir(dt: 'dirtree_t *', path: str) -> None

```

Dirtree: a directory has been deleted.

Args: dt (dirtree_t): The dirtree object. path (str): Path to the deleted directory.

#### dirtree_rminode

```
dirtree_rminode(dt: 'dirtree_t *', inode: inode_t) -> None

```

Dirtree: an inode became unavailable.

#### dirtree_segm_moved

```
dirtree_segm_moved(dt: 'dirtree_t *') -> None

```

Dirtree: inodes were changed due to a segment movement or a program rebasing.

#### extlang_changed

```
extlang_changed(
    kind: int, el: 'extlang_t *', idx: int
) -> None

```

The list of extlangs or the default extlang was changed.

Args: kind (int): 0: extlang installed, 1: extlang removed, 2: default extlang changed. el (extlang_t \*): Pointer to the extlang affected. idx (int): Extlang index.

#### extra_cmt_changed

```
extra_cmt_changed(
    ea: ea_t, line_idx: int, cmt: str
) -> None

```

An extra comment has been changed.

Args: ea (ea_t): Address of the item. line_idx (int): Line index of the comment. cmt (str): The comment text.

#### flow_chart_created

```
flow_chart_created(fc: qflow_chart_t) -> None

```

GUI has retrieved a function flow chart. Plugins may modify the flow chart in this callback.

Args: fc (qflow_chart_t \*): Function flow chart.

#### frame_created

```
frame_created(func_ea: ea_t) -> None

```

A function frame has been created.

#### frame_deleted

```
frame_deleted(pfn: 'func_t *') -> None

```

The kernel has deleted a function frame.

Args: pfn (func_t \*): The function whose frame was deleted.

#### frame_expanded

```
frame_expanded(
    func_ea: ea_t, udm_tid: tid_t, delta: adiff_t
) -> None

```

A frame type has been expanded or shrunk.

#### frame_udm_changed

```
frame_udm_changed(
    func_ea: ea_t,
    udm_tid: tid_t,
    udmold: udm_t,
    udmnew: udm_t,
) -> None

```

Frame member has been changed.

#### frame_udm_created

```
frame_udm_created(func_ea: ea_t, udm: udm_t) -> None

```

Frame member has been added.

#### frame_udm_deleted

```
frame_udm_deleted(
    func_ea: ea_t, udm_tid: tid_t, udm: udm_t
) -> None

```

Frame member has been deleted.

#### frame_udm_renamed

```
frame_udm_renamed(
    func_ea: ea_t, udm: udm_t, oldname: str
) -> None

```

Frame member has been renamed.

#### func_added

```
func_added(pfn: 'func_t *') -> None

```

The kernel has added a function.

Args: pfn (func_t \*): The function that was added.

#### func_deleted

```
func_deleted(func_ea: ea_t) -> None

```

A function has been deleted.

Args: func_ea (ea_t): Address of the deleted function.

#### func_noret_changed

```
func_noret_changed(pfn: 'func_t *') -> None

```

FUNC_NORET bit has been changed.

Args: pfn (func_t \*): The function whose noreturn bit was changed.

#### func_tail_appended

```
func_tail_appended(
    pfn: 'func_t *', tail: 'func_t *'
) -> None

```

A function tail chunk has been appended.

Args: pfn (func_t *): The function to which the tail was appended. tail (func_t* ): The tail function chunk.

#### func_tail_deleted

```
func_tail_deleted(pfn: 'func_t *', tail_ea: ea_t) -> None

```

A function tail chunk has been removed.

Args: pfn (func_t \*): The function from which the tail was removed. tail_ea (ea_t): The start address of the tail that was deleted.

#### func_updated

```
func_updated(pfn: 'func_t *') -> None

```

The kernel has updated a function.

Args: pfn (func_t \*): The function that was updated.

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### idasgn_loaded

```
idasgn_loaded(short_sig_name: str) -> None

```

FLIRT signature has been loaded for normal processing (not for recognition of startup sequences).

Args: short_sig_name (str): The short signature name.

#### idasgn_matched_ea

```
idasgn_matched_ea(
    ea: ea_t, name: str, lib_name: str
) -> None

```

A FLIRT match has been found.

#### item_color_changed

```
item_color_changed(ea: ea_t, color: bgcolor_t) -> None

```

An item color has been changed.

Args: ea (ea_t): Address of the item. color (bgcolor_t): The new color. If color == DEFCOLOR, then the color is deleted.

#### kernel_config_loaded

```
kernel_config_loaded(pass_number: int) -> None

```

This event is issued when ida.cfg is parsed.

Args: pass_number (int): Pass number.

#### loader_finished

```
loader_finished(
    li: 'linput_t *', neflags: uint16, filetypename: str
) -> None

```

External file loader finished its work. Use this event to augment the existing loader functionality.

Args: li (linput_t \*): Loader input pointer. neflags (uint16): Load file flags. filetypename (str): File type name.

#### local_type_renamed

```
local_type_renamed(
    ordinal: int, oldname: str, newname: str
) -> None

```

Local type has been renamed.

#### local_types_changed

```
local_types_changed(
    ltc: local_type_change_t, ordinal: int, name: str
) -> None

```

Local types have been changed.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### lt_edm_changed

```
lt_edm_changed(
    enumname: str,
    edm_tid: tid_t,
    edmold: edm_t,
    edmnew: edm_t,
) -> None

```

Local type enum member has been changed.

#### lt_edm_created

```
lt_edm_created(enumname: str, edm: edm_t) -> None

```

Local type enum member has been added.

#### lt_edm_deleted

```
lt_edm_deleted(
    enumname: str, edm_tid: tid_t, edm: edm_t
) -> None

```

Local type enum member has been deleted.

#### lt_edm_renamed

```
lt_edm_renamed(
    enumname: str, edm: edm_t, oldname: str
) -> None

```

Local type enum member has been renamed.

#### lt_udm_changed

```
lt_udm_changed(
    udtname: str,
    udm_tid: tid_t,
    udmold: udm_t,
    udmnew: udm_t,
) -> None

```

Local type UDT member has been changed.

#### lt_udm_created

```
lt_udm_created(udtname: str, udm: udm_t) -> None

```

Local type UDT member has been added.

#### lt_udm_deleted

```
lt_udm_deleted(
    udtname: str, udm_tid: tid_t, udm: udm_t
) -> None

```

Local type UDT member has been deleted.

#### lt_udm_renamed

```
lt_udm_renamed(
    udtname: str, udm: udm_t, oldname: str
) -> None

```

Local type UDT member has been renamed.

#### lt_udt_expanded

```
lt_udt_expanded(
    udtname: str, udm_tid: tid_t, delta: adiff_t
) -> None

```

A structure type has been expanded or shrunk.

#### make_code

```
make_code(insn: 'insn_t const *') -> None

```

An instruction is being created.

Args: insn (insn_t const \*): The instruction being created.

#### make_data

```
make_data(
    ea: ea_t, flags: flags64_t, tid: tid_t, len: asize_t
) -> None

```

A data item is being created.

Args: ea (ea_t): Effective address. flags (flags64_t): Item flags. tid (tid_t): Type ID. len (asize_t): Length in bytes.

#### op_ti_changed

```
op_ti_changed(
    ea: ea_t,
    n: int,
    type: 'type_t const *',
    fnames: 'p_list const *',
) -> None

```

An operand typestring (c/c++ prototype) has been changed.

Args: ea (ea_t): Address. n (int): Operand number. type (type_t const *): Type. fnames (p_list const* ): Field names.

#### op_type_changed

```
op_type_changed(ea: ea_t, n: int) -> None

```

An operand type (offset, hex, etc...) has been set or deleted.

Args: ea (ea_t): Address. n (int): Operand number (eventually OR'ed with OPND_OUTER or OPND_ALL).

#### range_cmt_changed

```
range_cmt_changed(
    kind: range_kind_t,
    a: range_t,
    cmt: str,
    repeatable: bool,
) -> None

```

Range comment has been changed.

Args: kind (range_kind_t): Kind of the range. a (range_t): The range. cmt (str): The comment text. repeatable (bool): True if the comment is repeatable.

#### renamed

```
renamed(
    ea: ea_t, new_name: str, local_name: bool, old_name: str
) -> None

```

The kernel has renamed a byte. See also the rename event.

Args: ea (ea_t): Effective address of the renamed item. new_name (str): New name (can be None). local_name (bool): Whether the new name is local. old_name (str): Old name (can be None).

#### savebase

```
savebase() -> None

```

The database is being saved.

#### segm_added

```
segm_added(s: 'segment_t *') -> None

```

A new segment has been created.

Args: s (segment_t \*): The newly created segment. See also adding_segm.

#### segm_attrs_updated

```
segm_attrs_updated(s: 'segment_t *') -> None

```

Segment attributes have been changed.

Args: s (segment_t \*): The segment whose attributes have been updated.

#### segm_class_changed

```
segm_class_changed(s: 'segment_t *', sclass: str) -> None

```

Segment class has been changed.

Args: s (segment_t \*): The segment whose class has changed. sclass (str): The new segment class.

#### segm_deleted

```
segm_deleted(
    start_ea: ea_t, end_ea: ea_t, flags: int
) -> None

```

A segment has been deleted.

Args: start_ea (ea_t): Start address of the deleted segment. end_ea (ea_t): End address of the deleted segment. flags (int): Segment flags.

#### segm_end_changed

```
segm_end_changed(s: 'segment_t *', oldend: ea_t) -> None

```

Segment end address has been changed.

Args: s (segment_t \*): The segment. oldend (ea_t): Old end address.

#### segm_moved

```
segm_moved(
    _from: ea_t,
    to: ea_t,
    size: asize_t,
    changed_netmap: bool,
) -> None

```

Segment has been moved.

Args: \_from (ea_t): Original segment start address. to (ea_t): New segment start address. size (asize_t): Size of the segment. changed_netmap (bool): See also idb_event::allsegs_moved.

#### segm_name_changed

```
segm_name_changed(s: 'segment_t *', name: str) -> None

```

Segment name has been changed.

Args: s (segment_t \*): The segment whose name has changed. name (str): The new segment name.

#### segm_start_changed

```
segm_start_changed(
    s: 'segment_t *', oldstart: ea_t
) -> None

```

Segment start address has been changed.

Args: s (segment_t \*): The segment. oldstart (ea_t): Old start address.

#### set_func_end

```
set_func_end(pfn: 'func_t *', new_end: ea_t) -> None

```

Function chunk end address will be changed.

Args: pfn (func_t \*): The function to modify. new_end (ea_t): The new end address.

#### set_func_start

```
set_func_start(pfn: 'func_t *', new_start: ea_t) -> None

```

Function chunk start address will be changed.

Args: pfn (func_t \*): The function to modify. new_start (ea_t): The new start address.

#### sgr_changed

```
sgr_changed(
    start_ea: ea_t,
    end_ea: ea_t,
    regnum: int,
    value: sel_t,
    old_value: sel_t,
    tag: uchar,
) -> None

```

The kernel has changed a segment register value.

Args: start_ea (ea_t): Start address of the affected range. end_ea (ea_t): End address of the affected range. regnum (int): Register number. value (sel_t): New value. old_value (sel_t): Previous value. tag (uchar): Segment register range tag.

#### sgr_deleted

```
sgr_deleted(
    start_ea: ea_t, end_ea: ea_t, regnum: int
) -> None

```

The kernel has deleted a segment register value.

Args: start_ea (ea_t): Start address of the range. end_ea (ea_t): End address of the range. regnum (int): Register number.

#### stkpnts_changed

```
stkpnts_changed(pfn: 'func_t *') -> None

```

Stack change points have been modified.

Args: pfn (func_t \*): The function whose stack points were modified.

#### tail_owner_changed

```
tail_owner_changed(
    tail: 'func_t *', owner_func: ea_t, old_owner: ea_t
) -> None

```

A tail chunk owner has been changed.

Args: tail (func_t \*): The tail function chunk. owner_func (ea_t): The new owner function address. old_owner (ea_t): The previous owner function address.

#### thunk_func_created

```
thunk_func_created(pfn: 'func_t *') -> None

```

A thunk bit has been set for a function.

Args: pfn (func_t \*): The thunk function created.

#### ti_changed

```
ti_changed(
    ea: ea_t,
    type: 'type_t const *',
    fnames: 'p_list const *',
) -> None

```

An item typestring (c/c++ prototype) has been changed.

Args: ea (ea_t): Address. type (type_t const *): Type. fnames (p_list const* ): Field names.

#### tryblks_updated

```
tryblks_updated(tbv: 'tryblks_t const *') -> None

```

Updated tryblk information.

Args: tbv (tryblks_t const \*): The updated try blocks.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

#### updating_tryblks

```
updating_tryblks(tbv: 'tryblks_t const *') -> None

```

About to update tryblk information.

Args: tbv (tryblks_t const \*): The try blocks being updated.

#### upgraded

```
upgraded(_from: int) -> None

```

The database has been upgraded and the receiver can upgrade its info as well.

### DebuggerHooks

```
DebuggerHooks()

```

Bases: `_BaseHooks`, `DBG_Hooks`

Convenience class for debugger events handling.

Methods:

- **`dbg_bpt`** – A user defined breakpoint was reached.
- **`dbg_bpt_changed`** – Breakpoint has been changed.
- **`dbg_exception`** – Debug exception.
- **`dbg_finished_loading_bpts`** – Finished loading breakpoint info from idb.
- **`dbg_information`** – Debug information.
- **`dbg_library_load`** – Called on library load.
- **`dbg_library_unload`** – Called on library unload.
- **`dbg_process_attach`** – Called on process attached.
- **`dbg_process_detach`** – Called on process detach.
- **`dbg_process_exit`** – Called on process exit.
- **`dbg_process_start`** – Called on process started.
- **`dbg_request_error`** – An error occurred during the processing of a request.
- **`dbg_run_to`** – Called on run to.
- **`dbg_started_loading_bpts`** – Started loading breakpoint info from idb.
- **`dbg_step_into`** – Called on step into.
- **`dbg_step_over`** – Called on step over.
- **`dbg_step_until_ret`** – Called on step until ret.
- **`dbg_suspend_process`** – The process is now suspended.
- **`dbg_thread_exit`** – Called on thread exit.
- **`dbg_thread_start`** – Called on thread start.
- **`dbg_trace`** – A step occurred (one instruction was executed).
- **`hook`** – Hook (activate) the event handlers.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`unhook`** – Un-hook (de-activate) the event handlers.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### dbg_bpt

```
dbg_bpt(tid: thid_t, bptea: ea_t) -> int

```

A user defined breakpoint was reached. Args: tid (thid_t): Thread ID. bptea (ea_t): Breakpoint address.

#### dbg_bpt_changed

```
dbg_bpt_changed(bptev_code: int, bpt: bpt_t) -> None

```

Breakpoint has been changed. Args: bptev_code (int): Breakpoint modification events. bpt (bpt_t): Breakpoint.

#### dbg_exception

```
dbg_exception(
    pid: pid_t,
    tid: thid_t,
    ea: ea_t,
    exc_code: int,
    exc_can_cont: bool,
    exc_ea: ea_t,
    exc_info: str,
) -> int

```

Debug exception.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. exc_code (int): Exception code. exc_can_cont (bool): Can continue. exc_ea (ea_t): Exception address. exc_info (str): Exception info.

#### dbg_finished_loading_bpts

```
dbg_finished_loading_bpts() -> None

```

Finished loading breakpoint info from idb.

#### dbg_information

```
dbg_information(
    pid: pid_t, tid: thid_t, ea: ea_t, info: str
) -> None

```

Debug information.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. info (str): Info string.

#### dbg_library_load

```
dbg_library_load(
    pid: pid_t,
    tid: thid_t,
    ea: ea_t,
    modinfo_name: str,
    modinfo_base: ea_t,
    modinfo_size: asize_t,
) -> None

```

Called on library load.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. modinfo_name (str): Module info name. modinfo_base (ea_t): Module info base address. modinfo_size (asize_t): Module info size.

#### dbg_library_unload

```
dbg_library_unload(
    pid: pid_t, tid: thid_t, ea: ea_t, info: str
) -> None

```

Called on library unload.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. info (str): Info string.

#### dbg_process_attach

```
dbg_process_attach(
    pid: pid_t,
    tid: thid_t,
    ea: ea_t,
    modinfo_name: str,
    modinfo_base: ea_t,
    modinfo_size: asize_t,
) -> None

```

Called on process attached. Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. modinfo_name (str): Module info name. modinfo_base (ea_t): Module info base address. modinfo_size (asize_t): Module info size.

#### dbg_process_detach

```
dbg_process_detach(
    pid: pid_t, tid: thid_t, ea: ea_t
) -> None

```

Called on process detach.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address.

#### dbg_process_exit

```
dbg_process_exit(
    pid: pid_t, tid: thid_t, ea: ea_t, exit_code: int
) -> None

```

Called on process exit.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. exit_code (int): Exit code.

#### dbg_process_start

```
dbg_process_start(
    pid: pid_t,
    tid: thid_t,
    ea: ea_t,
    modinfo_name: str,
    modinfo_base: ea_t,
    modinfo_size: asize_t,
) -> None

```

Called on process started.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. modinfo_name (str): Module info name. modinfo_base (ea_t): Module info base address. modinfo_size (asize_t): Module info size.

#### dbg_request_error

```
dbg_request_error(
    failed_command: int, failed_dbg_notification: int
) -> None

```

An error occurred during the processing of a request. Args: failed_command (ui_notification_t): The failed command. failed_dbg_notification (dbg_notification_t): The failed debugger notification.

#### dbg_run_to

```
dbg_run_to(pid: pid_t, tid: thid_t, ea: ea_t) -> None

```

Called on run to.

#### dbg_started_loading_bpts

```
dbg_started_loading_bpts() -> None

```

Started loading breakpoint info from idb.

#### dbg_step_into

```
dbg_step_into() -> None

```

Called on step into.

#### dbg_step_over

```
dbg_step_over() -> None

```

Called on step over.

#### dbg_step_until_ret

```
dbg_step_until_ret() -> None

```

Called on step until ret.

#### dbg_suspend_process

```
dbg_suspend_process() -> None

```

The process is now suspended.

#### dbg_thread_exit

```
dbg_thread_exit(
    pid: pid_t, tid: thid_t, ea: ea_t, exit_code: int
) -> None

```

Called on thread exit.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address. exit_code (int): Exit code.

#### dbg_thread_start

```
dbg_thread_start(pid: pid_t, tid: thid_t, ea: ea_t) -> None

```

Called on thread start.

Args: pid (pid_t): Process ID. tid (thid_t): Thread ID. ea (ea_t): Address.

#### dbg_trace

```
dbg_trace(tid: thid_t, ip: ea_t) -> int

```

A step occurred (one instruction was executed). This event notification is only generated if step tracing is enabled. Args: tid (thid_t): Thread ID. ip (ea_t): Current instruction pointer. Usually points after the executed instruction. Returns: int: 1 = do not log this trace event, 0 = log it.

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

### DecompilerHooks

```
DecompilerHooks()

```

Bases: `_BaseHooks`, `Hexrays_Hooks`

Convenience class for decompiler events handling.

Methods:

- **`begin_inlining`** – Starting to inline outlined functions.
- **`build_callinfo`** – Analyzing a call instruction.
- **`callinfo_built`** – A call instruction has been analyzed.
- **`calls_done`** – All calls have been analyzed.
- **`close_pseudocode`** – Pseudocode view is being closed.
- **`cmt_changed`** – Comment got changed.
- **`collect_warnings`** – Collect warning messages from plugins.
- **`combine`** – Trying to combine instructions of a basic block.
- **`create_hint`** – Create a hint for the current item.
- **`curpos`** – Current cursor position has been changed.
- **`double_click`** – Mouse double click.
- **`flowchart`** – Flowchart has been generated.
- **`func_printed`** – Function text has been generated.
- **`glbopt`** – Global optimization has been finished.
- **`hook`** – Hook (activate) the event handlers.
- **`inlined_func`** – A set of ranges got inlined.
- **`inlining_func`** – A set of ranges is going to be inlined.
- **`interr`** – Internal error has occurred.
- **`keyboard`** – Keyboard has been hit.
- **`locopt`** – Basic block level optimization has been finished.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`lvar_cmt_changed`** – Local variable comment got changed.
- **`lvar_mapping_changed`** – Local variable mapping got changed.
- **`lvar_name_changed`** – Local variable got renamed.
- **`lvar_type_changed`** – Local variable type got changed.
- **`maturity`** – Ctree maturity level is being changed.
- **`mba_maturity`** – Maturity level of an MBA was changed.
- **`microcode`** – Microcode has been generated.
- **`open_pseudocode`** – New pseudocode view has been opened.
- **`populating_popup`** – Populating popup menu. We can add menu items now.
- **`pre_structural`** – Structure analysis is starting.
- **`prealloc`** – Local variables: preallocation step begins.
- **`preoptimized`** – Microcode has been preoptimized.
- **`print_func`** – Printing ctree and generating text.
- **`prolog`** – Prolog analysis has been finished.
- **`refresh_pseudocode`** – Existing pseudocode text has been refreshed.
- **`resolve_stkaddrs`** – The optimizer is about to resolve stack addresses.
- **`right_click`** – Mouse right click.
- **`stkpnts`** – SP change points have been calculated.
- **`structural`** – Structural analysis has been finished.
- **`switch_pseudocode`** – Existing pseudocode view has been reloaded with a new function.
- **`text_ready`** – Decompiled text is ready.
- **`unhook`** – Un-hook (de-activate) the event handlers.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### begin_inlining

```
begin_inlining(cdg: codegen_t, decomp_flags: int) -> int

```

Starting to inline outlined functions. This is an opportunity to inline other ranges. Args: cdg (codegen_t): The code generator object. decomp_flags (int): Decompiler flags. Returns: int: Microcode error codes code.

#### build_callinfo

```
build_callinfo(
    blk: mblock_t, type: tinfo_t
) -> 'PyObject *'

```

Analyzing a call instruction. Args: blk (mblock_t): Block; blk->tail is the call. type (tinfo_t): Buffer for the output type.

#### callinfo_built

```
callinfo_built(blk: mblock_t) -> int

```

A call instruction has been analyzed. Args: blk (mblock_t): Block; blk->tail is the call.

#### calls_done

```
calls_done(mba: mba_t) -> int

```

All calls have been analyzed. This event is generated immediately after analyzing all calls, before any optimizations, call unmerging and block merging. Args: mba (mba_t): The microcode basic block array.

#### close_pseudocode

```
close_pseudocode(vu: vdui_t) -> int

```

Pseudocode view is being closed. Args: vu (vdui_t): The pseudocode UI object. Returns: int: 1 if the event has been handled.

#### cmt_changed

```
cmt_changed(
    cfunc: cfunc_t, loc: treeloc_t, cmt: str
) -> int

```

Comment got changed. Args: cfunc (cfunc_t): The decompiled function. loc (treeloc_t): The tree location of the comment. cmt (str): The new comment string. Returns: int: 1 if the event has been handled.

#### collect_warnings

```
collect_warnings(cfunc: cfunc_t) -> int

```

Collect warning messages from plugins. These warnings will be displayed at the function header, after the user-defined comments. Args: cfunc (cfunc_t): The cfunc object. Returns: int: Microcode error codes code.

#### combine

```
combine(blk: mblock_t, insn: minsn_t) -> int

```

Trying to combine instructions of a basic block. Args: blk (mblock_t): The basic block. insn (minsn_t): The instruction. Returns: int: 1 if combined the current instruction with a preceding one, -1 if the instruction should not be combined, 0 otherwise.

#### create_hint

```
create_hint(vu: vdui_t) -> 'PyObject *'

```

Create a hint for the current item. Args: vu (vdui_t): The pseudocode UI object. Returns: PyObject: 0 to continue collecting hints with other subscribers, 1 to stop collecting hints.

#### curpos

```
curpos(vu: vdui_t) -> int

```

Current cursor position has been changed. For example, by left-clicking or using keyboard. Args: vu (vdui_t): The pseudocode UI object. Returns: int: 1 if the event has been handled.

#### double_click

```
double_click(vu: vdui_t, shift_state: int) -> int

```

Mouse double click. Args: vu (vdui_t): The pseudocode UI object. shift_state (int): Keyboard shift state. Returns: int: 1 if the event has been handled.

#### flowchart

```
flowchart(
    fc: qflow_chart_t,
    mba: mba_t,
    reachable_blocks: bitset_t,
    decomp_flags: int,
) -> int

```

Flowchart has been generated. Args: fc (qflow_chart_t): The flowchart object. mba (mba_t): The microcode basic block array. reachable_blocks (bitset_t): Set of reachable blocks. decomp_flags (int): Decompiler flags. Returns: int: Microcode error code.

#### func_printed

```
func_printed(cfunc: cfunc_t) -> int

```

Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp). COLOR_ADDR is used to store pointers to ctree items. Args: cfunc (cfunc_t): The cfunc object.

#### glbopt

```
glbopt(mba: mba_t) -> int

```

Global optimization has been finished. If microcode is modified, MERR_LOOP must be returned. It will cause a complete restart of the optimization. Args: mba (mba_t): The microcode basic block array. Returns: int: Microcode error codes code.

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### inlined_func

```
inlined_func(
    cdg: codegen_t,
    blk: int,
    mbr: mba_ranges_t,
    i1: int,
    i2: int,
) -> int

```

A set of ranges got inlined. Args: cdg (codegen_t): The code generator object. blk (int): The block containing call/jump to inline. mbr (mba_ranges_t): The range to inline. i1 (int): Block number of the first inlined block. i2 (int): Block number of the last inlined block (excluded). Returns: int: Microcode error codes code.

#### inlining_func

```
inlining_func(
    cdg: codegen_t, blk: int, mbr: mba_ranges_t
) -> int

```

A set of ranges is going to be inlined. Args: cdg (codegen_t): The code generator object. blk (int): The block containing call/jump to inline. mbr (mba_ranges_t): The range to inline. Returns: int: Microcode error codes code.

#### interr

```
interr(errcode: int) -> int

```

Internal error has occurred. Args: errcode (int): The error code.

#### keyboard

```
keyboard(
    vu: vdui_t, key_code: int, shift_state: int
) -> int

```

Keyboard has been hit. Args: vu (vdui_t): The pseudocode UI object. key_code (int): Virtual key code. shift_state (int): Keyboard shift state. Returns: int: 1 if the event has been handled.

#### locopt

```
locopt(mba: mba_t) -> int

```

Basic block level optimization has been finished. Args: mba (mba_t): The microcode basic block array. Returns: int: Microcode error codes code.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### lvar_cmt_changed

```
lvar_cmt_changed(vu: vdui_t, v: lvar_t, cmt: str) -> int

```

Local variable comment got changed. Args: vu (vdui_t): The pseudocode UI object. v (lvar_t): The local variable object. cmt (str): The new comment. Note: It is possible to read/write user settings for lvars directly from the idb. Returns: int: 1 if the event has been handled.

#### lvar_mapping_changed

```
lvar_mapping_changed(
    vu: vdui_t, frm: lvar_t, to: lvar_t
) -> int

```

Local variable mapping got changed. Args: vu (vdui_t): The pseudocode UI object. frm (lvar_t): The original local variable. to (lvar_t): The mapped local variable. Note: It is possible to read/write user settings for lvars directly from the idb. Returns: int: 1 if the event has been handled.

#### lvar_name_changed

```
lvar_name_changed(
    vu: vdui_t, v: lvar_t, name: str, is_user_name: bool
) -> int

```

Local variable got renamed. Args: vu (vdui_t): The pseudocode UI object. v (lvar_t): The local variable object. name (str): The new variable name. is_user_name (bool): True if this is a user-provided name. Note: It is possible to read/write user settings for lvars directly from the idb. Returns: int: 1 if the event has been handled.

#### lvar_type_changed

```
lvar_type_changed(
    vu: vdui_t, v: lvar_t, tinfo: tinfo_t
) -> int

```

Local variable type got changed. Args: vu (vdui_t): The pseudocode UI object. v (lvar_t): The local variable object. tinfo (tinfo_t): The new type info. Note: It is possible to read/write user settings for lvars directly from the idb. Returns: int: 1 if the event has been handled.

#### maturity

```
maturity(
    cfunc: cfunc_t, new_maturity: ctree_maturity_t
) -> int

```

Ctree maturity level is being changed. Args: cfunc (cfunc_t): The cfunc object. new_maturity (ctree_maturity_t): New ctree maturity level.

#### mba_maturity

```
mba_maturity(mba: mba_t, reqmat: mba_maturity_t) -> int

```

Maturity level of an MBA was changed. Args: mba (mba_t): The microcode block. reqmat (mba_maturity_t): Requested maturity level. Returns: int: Microcode error codes code.

#### microcode

```
microcode(mba: mba_t) -> int

```

Microcode has been generated. Args: mba (mba_t): The microcode basic block array. Returns: int: Microcode error codes code.

#### open_pseudocode

```
open_pseudocode(vu: vdui_t) -> int

```

New pseudocode view has been opened. Args: vu (vdui_t): The pseudocode UI object. Returns: int: Microcode error codes code.

#### populating_popup

```
populating_popup(
    widget: 'TWidget *',
    popup_handle: 'TPopupMenu *',
    vu: vdui_t,
) -> int

```

Populating popup menu. We can add menu items now. Args: widget (TWidget): The widget object. popup_handle (TPopupMenu): The popup menu handle. vu (vdui_t): The pseudocode UI object. Returns: int: 1 if the event has been handled.

#### pre_structural

```
pre_structural(
    ct: 'control_graph_t *',
    cfunc: cfunc_t,
    g: simple_graph_t,
) -> int

```

Structure analysis is starting. Args: ct (control_graph_t \*): Control graph (input/output). cfunc (cfunc_t): The current function (input). g (simple_graph_t): Control flow graph (input). Returns: int: Microcode error codes code; MERR_BLOCK means that the analysis has been performed by a plugin.

#### prealloc

```
prealloc(mba: mba_t) -> int

```

Local variables: preallocation step begins. Args: mba (mba_t): The microcode basic block array. This event may occur several times. Returns: int: 1 if microcode was modified, otherwise negative values are Microcode error codes.

#### preoptimized

```
preoptimized(mba: mba_t) -> int

```

Microcode has been preoptimized. Args: mba (mba_t): The microcode basic block array. Returns: int: Microcode error codes code.

#### print_func

```
print_func(cfunc: cfunc_t, vp: vc_printer_t) -> int

```

Printing ctree and generating text. It is forbidden to modify ctree at this event. Args: cfunc (cfunc_t): The cfunc object. vp (vc_printer_t): The vc_printer object. Returns: int: 1 if text has been generated by the plugin.

#### prolog

```
prolog(
    mba: mba_t,
    fc: qflow_chart_t,
    reachable_blocks: bitset_t,
    decomp_flags: int,
) -> int

```

Prolog analysis has been finished. Args: mba (mba_t): The microcode basic block array. fc (qflow_chart_t): The function's flowchart. reachable_blocks (bitset_t): Set of reachable blocks. decomp_flags (int): Decompiler flags. Returns: int: Microcode error codes code. This event is generated for each inlined range as well.

#### refresh_pseudocode

```
refresh_pseudocode(vu: vdui_t) -> int

```

Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is forbidden in this event. Args: vu (vdui_t): The pseudocode UI object. See also hxe_text_ready, which happens earlier. Returns: int: Microcode error codes code.

#### resolve_stkaddrs

```
resolve_stkaddrs(mba: mba_t) -> int

```

The optimizer is about to resolve stack addresses. Args: mba (mba_t): The microcode basic block array.

#### right_click

```
right_click(vu: vdui_t) -> int

```

Mouse right click. Use hxe_populating_popup instead, in case you want to add items in the popup menu. Args: vu (vdui_t): The pseudocode UI object. Returns: int: 1 if the event has been handled.

#### stkpnts

```
stkpnts(mba: mba_t, *sps: 'stkpnts*t *') -> int

```

SP change points have been calculated. Args: mba (mba_t): The microcode basic block array. *sps (stkpnts*t \*): Stack pointer change points. Returns: int: Microcode error codes code. This event is generated for each inlined range as well.

#### structural

```
structural(ct: 'control_graph_t *') -> int

```

Structural analysis has been finished. Args: ct (control_graph_t \*): The control graph.

#### switch_pseudocode

```
switch_pseudocode(vu: vdui_t) -> int

```

Existing pseudocode view has been reloaded with a new function. Its text has not been refreshed yet, only cfunc and mba pointers are ready. Args: vu (vdui_t): The pseudocode UI object. Returns: int: Microcode error codes code.

#### text_ready

```
text_ready(vu: vdui_t) -> int

```

Decompiled text is ready. This event can be used to modify the output text (sv). Obsolete. Please use hxe_func_printed instead. Args: vu (vdui_t): The pseudocode UI object. Returns: int: 1 if the event has been handled.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

### ProcessorHooks

```
ProcessorHooks()

```

Bases: `_BaseHooks`, `IDP_Hooks`

Convenience class for IDP (processor) events handling.

Methods:

- **`ev_add_cref`** – A code reference is being created.
- **`ev_add_dref`** – A data reference is being created.
- **`ev_adjust_argloc`** – Adjust argloc according to its type/size and platform endianess.
- **`ev_adjust_libfunc_ea`** – Called when a signature module has been matched against bytes in the database.
- **`ev_adjust_refinfo`** – Called from apply_fixup before converting operand to reference.
- **`ev_ana_insn`** – Analyze one instruction and fill the 'out' structure.
- **`ev_analyze_prolog`** – Analyzes function prolog/epilog and updates purge and function attributes.
- **`ev_arch_changed`** – The loader finished parsing arch-related info;
- **`ev_arg_addrs_ready`** – Argument address info is ready.
- **`ev_asm_installed`** – After setting a new assembler.
- **`ev_assemble`** – Assemble an instruction. Display a warning if an error is found.
- **`ev_auto_queue_empty`** – One analysis queue is empty.
- **`ev_calc_arglocs`** – Calculate function argument locations.
- **`ev_calc_cdecl_purged_bytes`** – Calculate number of purged bytes after call.
- **`ev_calc_next_eas`** – Calculate list of addresses the instruction in 'insn' may pass control to.
- **`ev_calc_purged_bytes`** – Calculate number of purged bytes by the given function type.
- **`ev_calc_retloc`** – Calculate return value location.
- **`ev_calc_spdelta`** – Calculate amount of change to SP for the given instruction.
- **`ev_calc_step_over`** – Calculate the address of the instruction which will be executed after "step over".
- **`ev_calc_switch_cases`** – Calculate case values and targets for a custom jump table.
- **`ev_calc_varglocs`** – Calculate locations of the arguments that correspond to '...'.
- **`ev_calcrel`** – Reserved.
- **`ev_can_have_type`** – Can the operand have a type (offset, segment, decimal, etc)?
- **`ev_clean_tbit`** – Clear the TF bit after an insn like pushf stored it in memory.
- **`ev_cmp_operands`** – Compare instruction operands.
- **`ev_coagulate`** – Try to define some unexplored bytes.
- **`ev_coagulate_dref`** – Data reference is being analyzed. Plugin may correct 'code_ea'
- **`ev_create_flat_group`** – Create special segment representing the flat group.
- **`ev_create_func_frame`** – Create a function frame for a newly created function.
- **`ev_create_merge_handlers`** – Create merge handlers, if needed.
- **`ev_create_switch_xrefs`** – Create xrefs for a custom jump table.
- **`ev_creating_segm`** – A new segment is about to be created.
- **`ev_cvt64_hashval`** – Perform 32-64 conversion for a hash value.
- **`ev_cvt64_supval`** – Perform 32-64 conversion for a netnode array element.
- **`ev_decorate_name`** – Decorate or undecorate a C symbol name.
- **`ev_del_cref`** – A code reference is being deleted.
- **`ev_del_dref`** – A data reference is being deleted.
- **`ev_delay_slot_insn`** – Get delay slot instruction.
- **`ev_demangle_name`** – Demangle a C++ (or other language) name into a user-readable string.
- **`ev_emu_insn`** – Emulate an instruction, create cross-references, plan subsequent analyses,
- **`ev_endbinary`** – Called after IDA has loaded a binary file.
- **`ev_ending_undo`** – Ended undoing/redoing an action.
- **`ev_equal_reglocs`** – Are two register arglocs the same?
- **`ev_extract_address`** – Extract address from a string.
- **`ev_find_op_value`** – Find operand value via a register tracker.
- **`ev_find_reg_value`** – Find register value via a register tracker.
- **`ev_func_bounds`** – Called after find_func_bounds() finishes. The module may fine-tune the function bounds.
- **`ev_gen_asm_or_lst`** – Generating asm or lst file. Called twice: at the beginning and at the end of
- **`ev_gen_map_file`** – Generate map file. If not implemented, the kernel itself will create the map file.
- **`ev_gen_regvar_def`** – Generate register variable definition line.
- **`ev_gen_src_file_lnnum`** – Callback: generate an analog of '#line 123'.
- **`ev_gen_stkvar_def`** – Generate stack variable definition line.
- **`ev_get_abi_info`** – Get all possible ABI names and optional extensions for given compiler.
- **`ev_get_autocmt`** – Callback: get dynamic auto comment.
- **`ev_get_bg_color`** – Get item background color.
- **`ev_get_cc_regs`** – Get register allocation convention for given calling convention.
- **`ev_get_code16_mode`** – Get ISA 16-bit mode.
- **`ev_get_dbr_opnum`** – Get the number of the operand to be displayed in the debugger reference view (text mode).
- **`ev_get_default_enum_size`** – Get default enum size.
- **`ev_get_frame_retsize`** – Get size of function return address in bytes.
- **`ev_get_macro_insn_head`** – Calculate the start of a macro instruction.
- **`ev_get_operand_string`** – Request text string for operand (cli, java, ...).
- **`ev_get_procmod`** – Get pointer to the processor module object.
- **`ev_get_reg_accesses`** – Get info about registers that are used/changed by an instruction.
- **`ev_get_reg_info`** – Get register information by its name.
- **`ev_get_reg_name`** – Generate text representation of a register.
- **`ev_get_simd_types`** – Get SIMD-related types according to given attributes and/or argument location.
- **`ev_get_stkarg_area_info`** – Get metrics of the stack argument area.
- **`ev_get_stkvar_scale_factor`** – Should stack variable references be multiplied by a coefficient
- **`ev_getreg`** – IBM PC only internal request. Should never be used for other purposes. Get register value
- **`ev_init`** – The IDP module is just loaded.
- **`ev_insn_reads_tbit`** – Check if insn will read the TF bit.
- **`ev_is_addr_insn`** – Does the instruction calculate some address using an immediate operand?
- **`ev_is_align_insn`** – Checks if the instruction is created only for alignment purposes.
- **`ev_is_alloca_probe`** – Checks if the function at 'ea' behaves as \_\_alloca_probe.
- **`ev_is_basic_block_end`** – Checks if the current instruction is the end of a basic block.
- **`ev_is_call_insn`** – Checks if the instruction is a "call".
- **`ev_is_cond_insn`** – Checks if the instruction is conditional.
- **`ev_is_control_flow_guard`** – Detect if an instruction is a "thunk call" to a flow guard function
- **`ev_is_far_jump`** – Checks if the instruction is an indirect far jump or call instruction.
- **`ev_is_indirect_jump`** – Determine if instruction is an indirect jump.
- **`ev_is_insn_table_jump`** – Reserved.
- **`ev_is_jump_func`** – Determine if the function is a trivial "jump" function.
- **`ev_is_ret_insn`** – Checks if the instruction is a "return".
- **`ev_is_sane_insn`** – Checks if the instruction is sane for the current file type.
- **`ev_is_sp_based`** – Check whether the operand is relative to stack pointer or frame pointer.
- **`ev_is_switch`** – Find 'switch' idiom or override processor module's decision.
- **`ev_last_cb_before_loader`** –
- **`ev_loader`** – This code and higher ones are reserved for the loaders.
- **`ev_lower_func_type`** – Get function arguments to convert to pointers when lowering prototype.
- **`ev_max_ptr_size`** – Get maximal size of a pointer in bytes.
- **`ev_may_be_func`** – Checks if a function can start at this instruction.
- **`ev_may_show_sreg`** – The kernel wants to display the segment registers in the messages window.
- **`ev_moving_segm`** – May the kernel move the segment?
- **`ev_newasm`** – Called before setting a new assembler.
- **`ev_newbinary`** – Called when IDA is about to load a binary file.
- **`ev_newfile`** – Called when a new file has been loaded.
- **`ev_newprc`** – Called before changing processor type.
- **`ev_next_exec_insn`** – Get next address to be executed.
- **`ev_oldfile`** – Called when an old file has been loaded.
- **`ev_out_assumes`** – Produce assume directives when segment register value changes.
- **`ev_out_data`** – Generate text representation of data items.
- **`ev_out_footer`** – Produce the end of disassembled text.
- **`ev_out_header`** – Produce the start of disassembled text.
- **`ev_out_insn`** – Generate text representation of an instruction in 'ctx.insn'.
- **`ev_out_label`** – The kernel is going to generate an instruction label line or a function header.
- **`ev_out_mnem`** – Generate instruction mnemonics.
- **`ev_out_operand`** – Generate text representation of an instruction operand.
- **`ev_out_segend`** – Produce the end of a segment in disassembled output.
- **`ev_out_segstart`** – Produce the start of a segment in disassembled output.
- **`ev_out_special_item`** – Generate text representation of an item in a special segment.
- **`ev_privrange_changed`** – Privrange interval has been moved to a new location.
- **`ev_realcvt`** – Floating point to IEEE conversion.
- **`ev_rename`** – The kernel is going to rename a byte.
- **`ev_replaying_undo`** – Replaying an undo/redo buffer.
- **`ev_set_code16_mode`** – Set ISA 16-bit mode (for some processors, e.g. ARM Thumb, PPC VLE, MIPS16).
- **`ev_set_proc_options`** – Called if the user specified an option string in the command line or via SetProcessorType.
- **`ev_setup_til`** – Setup default type libraries.
- **`ev_str2reg`** – Convert a register name to a register number.
- **`ev_term`** – The IDP module is being unloaded.
- **`ev_treat_hindering_item`** – An item hinders creation of another item.
- **`ev_undefine`** – An item in the database (instruction or data) is being deleted.
- **`ev_update_call_stack`** – Calculate the call stack trace for the given thread.
- **`ev_use_arg_types`** – Use information about callee arguments.
- **`ev_use_regarg_type`** – Use information about register argument.
- **`ev_use_stkarg_type`** – Use information about a stack argument.
- **`ev_validate_flirt_func`** – FLIRT has recognized a library function.
- **`ev_verify_noreturn`** – The kernel wants to set 'noreturn' flags for a function.
- **`ev_verify_sp`** – Called after all function instructions have been analyzed.
- **`hook`** – Hook (activate) the event handlers.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`unhook`** – Un-hook (de-activate) the event handlers.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### ev_add_cref

```
ev_add_cref(_from: ea_t, to: ea_t, type: cref_t) -> int

```

A code reference is being created.

Args: \_from (ea_t): Source address. to (ea_t): Target address. type (cref_t): Reference type.

Returns: int: \<0 to cancel cref creation, 0 to not implement or continue.

#### ev_add_dref

```
ev_add_dref(_from: ea_t, to: ea_t, type: dref_t) -> int

```

A data reference is being created.

Args: \_from (ea_t): Source address. to (ea_t): Target address. type (dref_t): Reference type.

Returns: int: \<0 to cancel dref creation, 0 to not implement or continue.

#### ev_adjust_argloc

```
ev_adjust_argloc(
    argloc: argloc_t, optional_type: tinfo_t, size: int
) -> int

```

Adjust argloc according to its type/size and platform endianess.

Args: argloc (argloc_t): Argument location, inout. optional_type (tinfo_t): Type information (may be None). size (int): Argument size; ignored if type is not None.

Returns: int: 0 if not implemented, 1 if ok, -1 on error.

#### ev_adjust_libfunc_ea

```
ev_adjust_libfunc_ea(
    sig: 'idasgn_t const *',
    libfun: 'libfunc_t const *',
    ea: 'ea_t *',
) -> int

```

Called when a signature module has been matched against bytes in the database. This is used to compute the offset at which a particular module's libfunc should be applied.

Args: sig (idasgn_t const *): Signature. libfun (libfunc_t const* ): Library function. ea (ea_t \*): Pointer to effective address (may be modified).

Returns: int: 1 if the address was modified, \<=0 if not (use default algorithm).

#### ev_adjust_refinfo

```
ev_adjust_refinfo(
    ri: refinfo_t,
    ea: ea_t,
    n: int,
    fd: 'fixup_data_t const *',
) -> int

```

Called from apply_fixup before converting operand to reference.

Can be used for changing the reference info (e.g. PPC module adds REFINFO_NOBASE for some references).

Args: ri (refinfo_t): Reference info. ea (ea_t): Instruction address. n (int): Operand number. fd (fixup_data_t const \*): Fixup data.

Returns: int: \<0 to not create an offset, 0 if not implemented or refinfo adjusted.

#### ev_ana_insn

```
ev_ana_insn(out: 'insn_t *') -> bool

```

Analyze one instruction and fill the 'out' structure.

This function shouldn't change the database, flags, or anything else. All such actions should be performed only by ev_emu_insn(). insn_t::ea contains address of instruction to analyze.

Args: out (insn_t \*): Structure to be filled with the analyzed instruction.

Returns: bool: Length of the instruction in bytes, or 0 if instruction can't be decoded.

#### ev_analyze_prolog

```
ev_analyze_prolog(ea: ea_t) -> int

```

Analyzes function prolog/epilog and updates purge and function attributes.

Args: ea (ea_t): Start address of the function.

Returns: int: 1 for ok, 0 if not implemented.

#### ev_arch_changed

```
ev_arch_changed() -> int

```

The loader finished parsing arch-related info; processor module might use it to finish init.

Returns: int: 1 if success, 0 if not implemented or failed.

#### ev_arg_addrs_ready

```
ev_arg_addrs_ready(
    caller: ea_t, n: int, tif: tinfo_t, addrs: 'ea_t *'
) -> int

```

Argument address info is ready.

Args: caller (ea_t): Address of the caller. n (int): Number of formal arguments. tif (tinfo_t): Call prototype. addrs (ea_t \*): Argument initialization addresses.

Returns: int: \<0 to avoid saving into idb; other values mean "ok to save".

#### ev_asm_installed

```
ev_asm_installed(asmnum: int) -> int

```

After setting a new assembler.

Args: asmnum (int): Assembler number (see also ev_newasm).

Returns: int: 1 if ok, 0 if not implemented.

#### ev_assemble

```
ev_assemble(
    ea: ea_t, cs: ea_t, ip: ea_t, use32: bool, line: str
) -> 'PyObject *'

```

Assemble an instruction. Display a warning if an error is found.

Args: ea (ea_t): Linear address of instruction. cs (ea_t): Code segment of instruction. ip (ea_t): Instruction pointer of instruction. use32 (bool): Is it a 32-bit segment? line (str): Line to assemble.

Returns: PyObject\*: Size of the instruction in bytes.

#### ev_auto_queue_empty

```
ev_auto_queue_empty(type: atype_t) -> int

```

One analysis queue is empty.

Args: type (atype_t): The queue type.

Returns: int: See also idb_event::auto_empty_finally.

#### ev_calc_arglocs

```
ev_calc_arglocs(fti: func_type_data_t) -> int

```

Calculate function argument locations.

This callback should fill retloc, all arglocs, and stkargs. This callback is never called for CM_CC_SPECIAL functions.

Args: fti (func_type_data_t): Points to the func type info.

Returns: int: 0 if not implemented, 1 if ok, -1 on error.

#### ev_calc_cdecl_purged_bytes

```
ev_calc_cdecl_purged_bytes(ea: ea_t) -> int

```

Calculate number of purged bytes after call.

Args: ea (ea_t): Address of the call instruction.

Returns: int: Number of purged bytes (usually add sp, N).

#### ev_calc_next_eas

```
ev_calc_next_eas(
    res: 'eavec_t *', insn: 'insn_t const *', over: bool
) -> int

```

Calculate list of addresses the instruction in 'insn' may pass control to.

This callback is required for source level debugging.

Args: res (eavec_t *): Output array for the results. insn (insn_t const* ): The instruction. over (bool): Calculate for step over (ignore call targets).

Returns: int: \<0 if incalculable (indirect jumps, for example),

> =0 for the number of addresses of called functions in the array. They must be put at the beginning of the array (0 if over=True).

#### ev_calc_purged_bytes

```
ev_calc_purged_bytes(
    p_purged_bytes: 'int *', fti: func_type_data_t
) -> int

```

Calculate number of purged bytes by the given function type.

Args: p_purged_bytes (int \*): Pointer to output value. fti (func_type_data_t): Function type details.

Returns: int: 1 if handled, 0 if not implemented.

#### ev_calc_retloc

```
ev_calc_retloc(
    retloc: argloc_t, rettype: tinfo_t, cc: callcnv_t
) -> int

```

Calculate return value location.

Args: retloc (argloc_t): Output argument location. rettype (tinfo_t): Return type information. cc (callcnv_t): Calling convention.

Returns: int: 0 if not implemented, 1 if ok, -1 on error.

#### ev_calc_spdelta

```
ev_calc_spdelta(
    spdelta: 'sval_t *', insn: 'insn_t const *'
) -> int

```

Calculate amount of change to SP for the given instruction. This event is required to decompile code snippets.

Args: spdelta (sval_t *): Output stack pointer delta. insn (insn_t const* ): The instruction.

Returns: int: 1 for ok, 0 if not implemented.

#### ev_calc_step_over

```
ev_calc_step_over(target: 'ea_t *', ip: ea_t) -> int

```

Calculate the address of the instruction which will be executed after "step over".

The kernel will put a breakpoint there. If the step over is equal to step into or we cannot calculate the address, return BADADDR.

Args: target (ea_t \*): Pointer to the answer. ip (ea_t): Instruction address.

Returns: int: 0 if unimplemented, 1 if implemented.

#### ev_calc_switch_cases

```
ev_calc_switch_cases(
    casevec: 'casevec_t *',
    targets: 'eavec_t *',
    insn_ea: ea_t,
    si: switch_info_t,
) -> int

```

Calculate case values and targets for a custom jump table.

Args: casevec (casevec_t *): Vector of case values (may be None). targets (eavec_t* ): Corresponding target addresses (may be None). insn_ea (ea_t): Address of the 'indirect jump' instruction. si (switch_info_t): Switch information.

Returns: int: 1: Success. \<=0: Failed.

#### ev_calc_varglocs

```
ev_calc_varglocs(
    ftd: func_type_data_t,
    aux_regs: regobjs_t,
    aux_stkargs: relobj_t,
    nfixed: int,
) -> int

```

Calculate locations of the arguments that correspond to '...'.

On some platforms, variadic calls require passing additional information (e.g., number of floating variadic arguments must be passed in rax on gcc-x64). The locations and values that constitute this additional information are returned in the buffers pointed by aux_regs and aux_stkargs.

Args: ftd (func_type_data_t): Info about all arguments (including varargs), inout. aux_regs (regobjs_t): Buffer for hidden register arguments, may be None. aux_stkargs (relobj_t): Buffer for hidden stack arguments, may be None. nfixed (int): Number of fixed arguments.

Returns: int: 0 if not implemented, 1 if ok, -1 on error.

#### ev_calcrel

```
ev_calcrel() -> int

```

Reserved.

Returns: int: Reserved return value.

#### ev_can_have_type

```
ev_can_have_type(op: 'op_t const *') -> int

```

Can the operand have a type (offset, segment, decimal, etc)?

For example, a register AX can't have a type, meaning the user can't change its representation. See bytes.hpp for information about types and flags.

Args: op (op_t const \*): The operand.

Returns: int: 0 if unknown, \<0 if no, 1 if yes.

#### ev_clean_tbit

```
ev_clean_tbit(
    ea: ea_t,
    getreg: 'processor_t::regval_getter_t *',
    regvalues: regval_t,
) -> int

```

Clear the TF bit after an insn like pushf stored it in memory.

Args: ea (ea_t): Instruction address. getreg (processor_t::regval_getter_t \*): Function to get register values. regvalues (regval_t): Register values array.

Returns: int: 1 if ok, 0 if failed.

#### ev_cmp_operands

```
ev_cmp_operands(
    op1: 'op_t const *', op2: 'op_t const *'
) -> int

```

Compare instruction operands.

Args: op1 (op_t const *): First operand. op2 (op_t const* ): Second operand.

Returns: int: 1 if equal, -1 if not equal, 0 if not implemented.

#### ev_coagulate

```
ev_coagulate(start_ea: ea_t) -> int

```

Try to define some unexplored bytes.

This notification will be called if the kernel tried all possibilities and could not find anything more useful than to convert to array of bytes. The module can help the kernel and convert the bytes into something more useful.

Args: start_ea (ea_t): Start address.

Returns: int: Number of converted bytes.

#### ev_coagulate_dref

```
ev_coagulate_dref(
    _from: ea_t,
    to: ea_t,
    may_define: bool,
    code_ea: 'ea_t *',
) -> int

```

Data reference is being analyzed. Plugin may correct 'code_ea' (e.g., for thumb mode refs, we clear the last bit).

Args: \_from (ea_t): Source address. to (ea_t): Target address. may_define (bool): Whether a definition may be created. code_ea (ea_t \*): Pointer to the effective code address (may be modified).

Returns: int: \<0 for failed dref analysis,

> 0 for done dref analysis, 0 to not implement or continue.

#### ev_create_flat_group

```
ev_create_flat_group(
    image_base: ea_t, bitness: int, dataseg_sel: sel_t
) -> int

```

Create special segment representing the flat group.

Args: image_base (ea_t): Image base. bitness (int): Bitness. dataseg_sel (sel_t): Data segment selector.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_create_func_frame

```
ev_create_func_frame(pfn: 'func_t *') -> int

```

Create a function frame for a newly created function.

Set up frame size, its attributes, etc.

Args: pfn (func_t \*): The function.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_create_merge_handlers

```
ev_create_merge_handlers(md: 'merge_data_t *') -> int

```

Create merge handlers, if needed. This event is generated immediately after opening idbs.

Args: md (merge_data_t \*): Merge data pointer.

Returns: int: Must be 0.

#### ev_create_switch_xrefs

```
ev_create_switch_xrefs(
    jumpea: ea_t, si: switch_info_t
) -> int

```

Create xrefs for a custom jump table.

Must be implemented if module uses custom jump tables, SWI_CUSTOM.

Args: jumpea (ea_t): Address of the jump instruction. si (switch_info_t): Switch information.

Returns: int: Must return 1.

#### ev_creating_segm

```
ev_creating_segm(seg: 'segment_t *') -> int

```

A new segment is about to be created.

Args: seg (segment_t \*): The segment being created.

Returns: int: 1 if OK, \<0 if the segment should not be created.

#### ev_cvt64_hashval

```
ev_cvt64_hashval(
    node: nodeidx_t,
    tag: uchar,
    name: str,
    data: 'uchar const *',
) -> int

```

Perform 32-64 conversion for a hash value.

Args: node (nodeidx_t): Node index. tag (uchar): Tag value. name (str): Name string. data (uchar const \*): Data pointer.

Returns: int: 0 if nothing was done, 1 if converted successfully, -1 for error (and message in errbuf).

#### ev_cvt64_supval

```
ev_cvt64_supval(
    node: nodeidx_t,
    tag: uchar,
    idx: nodeidx_t,
    data: 'uchar const *',
) -> int

```

Perform 32-64 conversion for a netnode array element.

Args: node (nodeidx_t): Node index. tag (uchar): Tag value. idx (nodeidx_t): Index. data (uchar const \*): Data pointer.

Returns: int: 0 if nothing was done, 1 if converted successfully, -1 for error (and message in errbuf).

#### ev_decorate_name

```
ev_decorate_name(
    name: str, mangle: bool, cc: int, optional_type: tinfo_t
) -> 'PyObject *'

```

Decorate or undecorate a C symbol name.

Args: name (str): Name of the symbol. mangle (bool): True to mangle, False to unmangle. cc (int): Calling convention (callcnv_t). optional_type (tinfo_t): Optional type information.

Returns: PyObject\*: 1 if success, 0 if not implemented or failed.

#### ev_del_cref

```
ev_del_cref(_from: ea_t, to: ea_t, expand: bool) -> int

```

A code reference is being deleted.

Args: \_from (ea_t): Source address. to (ea_t): Target address. expand (bool): Whether to expand the cref deletion.

Returns: int: \<0 to cancel cref deletion, 0 to not implement or continue.

#### ev_del_dref

```
ev_del_dref(_from: ea_t, to: ea_t) -> int

```

A data reference is being deleted.

Args: \_from (ea_t): Source address. to (ea_t): Target address.

Returns: int: \<0 to cancel dref deletion, 0 to not implement or continue.

#### ev_delay_slot_insn

```
ev_delay_slot_insn(
    ea: ea_t, bexec: bool, fexec: bool
) -> 'PyObject *'

```

Get delay slot instruction.

Args: ea (ea_t): Input: Instruction address in question. Output: If the answer is positive and the delay slot contains a valid instruction, returns the address of the delay slot instruction, else BADADDR (invalid instruction, e.g. a branch). bexec (bool): Execute slot if jumping, initially set to True. fexec (bool): Execute slot if not jumping, initially set to True.

Returns: PyObject\*: 1 for a positive answer, \<=0 for ordinary instruction.

#### ev_demangle_name

```
ev_demangle_name(
    name: str, disable_mask: int, demreq: int
) -> 'PyObject *'

```

Demangle a C++ (or other language) name into a user-readable string.

This event is called by demangle_name().

Args: name (str): Mangled name. disable_mask (int): Flags to inhibit parts of output or compiler info/other (see MNG\_). demreq (int): Operation to perform (demreq_type_t).

Returns: PyObject\*: 1 if success, 0 if not implemented.

#### ev_emu_insn

```
ev_emu_insn(insn: 'insn_t const *') -> bool

```

Emulate an instruction, create cross-references, plan subsequent analyses, modify flags, etc.

Upon entry, all information about the instruction is in the 'insn' structure.

Args: insn (insn_t const \*): Structure containing instruction information.

Returns: bool: True (1) if OK; False (-1) if the kernel should delete the instruction.

#### ev_endbinary

```
ev_endbinary(ok: bool) -> int

```

Called after IDA has loaded a binary file.

Args: ok (bool): True if file loaded successfully.

#### ev_ending_undo

```
ev_ending_undo(action_name: str, is_undo: bool) -> int

```

Ended undoing/redoing an action.

Args: action_name (str): Action that was undone or redone (not None). is_undo (bool): True if undo, False if redo.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_equal_reglocs

```
ev_equal_reglocs(a1: argloc_t, a2: argloc_t) -> int

```

Are two register arglocs the same?

Args: a1 (argloc_t): First argument location. a2 (argloc_t): Second argument location.

Returns: int: 1 if yes, -1 if no, 0 if not implemented.

#### ev_extract_address

```
ev_extract_address(
    out_ea: 'ea_t *',
    screen_ea: ea_t,
    string: str,
    position: size_t,
) -> int

```

Extract address from a string.

Args: out_ea (ea_t \*): Output address (pointer). screen_ea (ea_t): Current screen address. string (str): Source string. position (size_t): Position in the string.

Returns: int: 1 for success, 0 for standard algorithm, -1 for error.

#### ev_find_op_value

```
ev_find_op_value(
    pinsn: 'insn_t const *', opn: int
) -> 'PyObject *'

```

Find operand value via a register tracker.

The returned value in 'out' is valid before executing the instruction.

Args: pinsn (insn_t const \*): The instruction. opn (int): Operand index.

Returns: PyObject\*: 1 if implemented and value was found, 0 if not implemented, -1 if decoding failed or no value found.

#### ev_find_reg_value

```
ev_find_reg_value(
    pinsn: 'insn_t const *', reg: int
) -> 'PyObject *'

```

Find register value via a register tracker.

The returned value in 'out' is valid before executing the instruction.

Args: pinsn (insn_t const \*): The instruction. reg (int): Register index.

Returns: PyObject\*: 1 if implemented and value was found, 0 if not implemented, -1 if decoding failed or no value found.

#### ev_func_bounds

```
ev_func_bounds(
    possible_return_code: 'int *',
    pfn: 'func_t *',
    max_func_end_ea: ea_t,
) -> int

```

Called after find_func_bounds() finishes. The module may fine-tune the function bounds.

Args: possible_return_code (int *): In/out, possible return code. pfn (func_t* ): The function. max_func_end_ea (ea_t): From the kernel's point of view.

#### ev_gen_asm_or_lst

```
ev_gen_asm_or_lst(
    starting: bool,
    fp: 'FILE *',
    is_asm: bool,
    flags: int,
    outline: 'html_line_cb_t **',
) -> int

```

Generating asm or lst file. Called twice: at the beginning and at the end of listing generation. The processor module can intercept this event and adjust its output.

Args: starting (bool): True if beginning listing generation. fp (FILE *): Output file. is_asm (bool): True for assembler, False for listing. flags (int): Flags passed to gen_file(). outline (html_line_cb_t* \*): Pointer to pointer to outline callback. If defined, it will be used by the kernel to output the generated lines.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_gen_map_file

```
ev_gen_map_file(nlines: 'int *', fp: 'FILE *') -> int

```

Generate map file. If not implemented, the kernel itself will create the map file.

Args: nlines (int *): Number of lines in the map file (-1 means write error). fp (FILE* ): Output file.

Returns: int: 0 if not implemented, 1 for ok, -1 for write error.

#### ev_gen_regvar_def

```
ev_gen_regvar_def(
    outctx: 'outctx_t *', v: 'regvar_t *'
) -> int

```

Generate register variable definition line.

Args: outctx (outctx_t *): Output context. v (regvar_t* ): Register variable.

Returns: int: >0 if generated the definition text, 0 if not implemented.

#### ev_gen_src_file_lnnum

```
ev_gen_src_file_lnnum(
    outctx: 'outctx_t *', file: str, lnnum: size_t
) -> int

```

Callback: generate an analog of '#line 123'.

Args: outctx (outctx_t \*): Output context. file (str): Source file name (may be None). lnnum (size_t): Line number.

Returns: int: 1 if directive has been generated, 0 if not implemented.

#### ev_gen_stkvar_def

```
ev_gen_stkvar_def(
    outctx: 'outctx_t *', stkvar: udm_t, v: int, tid: tid_t
) -> int

```

Generate stack variable definition line.

Default line is: varname = type ptr value, where 'type' is one of byte, word, dword, qword, tbyte.

Args: outctx (outctx_t \*): Output context. stkvar (udm_t): Stack variable (const). v (int): Stack variable value. tid (tid_t): Stack variable TID.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_get_abi_info

```
ev_get_abi_info(comp: comp_t) -> int

```

Get all possible ABI names and optional extensions for given compiler.

abiname/option is a string entirely consisting of letters, digits and underscore.

Args: comp (comp_t): Compiler ID.

Returns: int: 0 if not implemented, 1 if ok.

#### ev_get_autocmt

```
ev_get_autocmt(insn: 'insn_t const *') -> 'PyObject *'

```

Callback: get dynamic auto comment.

Will be called if the autocomments are enabled and the comment retrieved from ida.int starts with '$!'. 'insn' contains valid info.

Args: insn (insn_t const \*): The instruction.

Returns: PyObject\*: 1 if a new comment has been generated, 0 if not handled (buffer not changed).

#### ev_get_bg_color

```
ev_get_bg_color(color: 'bgcolor_t *', ea: ea_t) -> int

```

Get item background color.

Plugins can hook this callback to color disassembly lines dynamically.

Args: color (bgcolor_t \*): Out, background color. ea (ea_t): Address.

Returns: int: 0 if not implemented, 1 if color set.

#### ev_get_cc_regs

```
ev_get_cc_regs(regs: callregs_t, cc: callcnv_t) -> int

```

Get register allocation convention for given calling convention.

Args: regs (callregs_t): Output for register allocation info. cc (callcnv_t): Calling convention.

Returns: int: 1 if handled, 0 if not implemented.

#### ev_get_code16_mode

```
ev_get_code16_mode(ea: ea_t) -> int

```

Get ISA 16-bit mode.

Args: ea (ea_t): Address to get the ISA mode.

Returns: int: 1 for 16-bit mode, 0 if not implemented or 32-bit mode.

#### ev_get_dbr_opnum

```
ev_get_dbr_opnum(
    opnum: 'int *', insn: 'insn_t const *'
) -> int

```

Get the number of the operand to be displayed in the debugger reference view (text mode).

Args: opnum (int *): Operand number (output, -1 means no such operand). insn (insn_t const* ): The instruction.

Returns: int: 0 if unimplemented, 1 if implemented.

#### ev_get_default_enum_size

```
ev_get_default_enum_size() -> int

```

Get default enum size.

Note: Not generated anymore. inf_get_cc_size_e() is used instead.

#### ev_get_frame_retsize

```
ev_get_frame_retsize(
    frsize: 'int *', pfn: 'func_t const *'
) -> int

```

Get size of function return address in bytes.

If not implemented, the kernel will assume: * 8 bytes for 64-bit function * 4 bytes for 32-bit function * 2 bytes otherwise

Args: frsize (int *): Out, frame size. pfn (func_t const* ): The function (cannot be nullptr).

Returns: int: 1 if ok, 0 if not implemented.

#### ev_get_macro_insn_head

```
ev_get_macro_insn_head(head: 'ea_t *', ip: ea_t) -> int

```

Calculate the start of a macro instruction.

This notification is called if IP points to the middle of an instruction.

Args: head (ea_t \*): Output answer; BADADDR means normal instruction. ip (ea_t): Instruction address.

Returns: int: 0 if unimplemented, 1 if implemented.

#### ev_get_operand_string

```
ev_get_operand_string(
    insn: 'insn_t const *', opnum: int
) -> 'PyObject *'

```

Request text string for operand (cli, java, ...).

Args: insn (insn_t const \*): The instruction. opnum (int): Operand number, -1 means any string operand.

Returns: PyObject\*: 0 if no string (or empty string), >0 for original string length (without terminating zero).

#### ev_get_procmod

```
ev_get_procmod() -> int

```

Get pointer to the processor module object.

All processor modules must implement this. The pointer is returned as size_t.

Returns: int: Processor module object pointer as size_t.

#### ev_get_reg_accesses

```
ev_get_reg_accesses(
    accvec: reg_accesses_t,
    insn: 'insn_t const *',
    flags: int,
) -> int

```

Get info about registers that are used/changed by an instruction.

Args: accvec (reg_accesses_t): Output info about accessed registers. insn (insn_t const \*): Instruction in question. flags (int): Reserved, must be 0.

Returns: int: -1 if accvec is None, 1 if found the requested access and filled accvec, 0 if not implemented.

#### ev_get_reg_info

```
ev_get_reg_info(
    main_regname: 'char const **',
    bitrange: bitrange_t,
    regname: str,
) -> int

```

Get register information by its name.

Example: "ah" returns:

- main_regname="eax"
- bitrange_t = { offset==8, nbits==8 }

This callback may be unimplemented if the register names are all present in processor_t::reg_names and they all have the same size.

Args: main_regname (char const \*\*): Output main register name. bitrange (bitrange_t): Output position and size of the value within 'main_regname' (empty bitrange == whole register). regname (str): Register name.

Returns: int: 1 if ok, -1 if failed (not found), 0 if unimplemented.

#### ev_get_reg_name

```
ev_get_reg_name(
    reg: int, width: size_t, reghi: int
) -> 'PyObject *'

```

Generate text representation of a register.

Most processor modules do not need to implement this callback. It is useful only if processor_t::reg_names[reg] does not provide the correct register name.

Args: reg (int): Internal register number as defined in the processor module. width (size_t): Register width in bytes. reghi (int): If not -1, returns the register pair.

Returns: PyObject\*: -1 if error, strlen(buf) if success.

#### ev_get_simd_types

```
ev_get_simd_types(
    out: 'simd_info_vec_t *',
    simd_attrs: simd_info_t,
    argloc: argloc_t,
    create_tifs: bool,
) -> int

```

Get SIMD-related types according to given attributes and/or argument location.

Args: out (simd_info_vec_t \*): Output vector of SIMD types. simd_attrs (simd_info_t): SIMD attributes (may be None). argloc (argloc_t): Argument location (may be None). create_tifs (bool): Return valid tinfo_t objects, create if necessary.

Returns: int: Number of found types, -1 on error.

#### ev_get_stkarg_area_info

```
ev_get_stkarg_area_info(
    out: stkarg_area_info_t, cc: callcnv_t
) -> int

```

Get metrics of the stack argument area.

Args: out (stkarg_area_info_t): Output info. cc (callcnv_t): Calling convention.

Returns: int: 1 if success, 0 if not implemented.

#### ev_get_stkvar_scale_factor

```
ev_get_stkvar_scale_factor() -> int

```

Should stack variable references be multiplied by a coefficient before being used in the stack frame?

Currently used by TMS320C55 because the references into the stack should be multiplied by 2.

Returns: int: Scaling factor, or 0 if not implemented.

#### ev_getreg

```
ev_getreg(regval: 'uval_t *', regnum: int) -> int

```

IBM PC only internal request. Should never be used for other purposes. Get register value by internal index.

Args: regval (uval_t \*): Output register value. regnum (int): Register number.

Returns: int: 1 for ok, 0 if not implemented, -1 for failed (undefined value or bad regnum).

#### ev_init

```
ev_init(idp_modname: str) -> int

```

The IDP module is just loaded.

Args: idp_modname (str): Processor module name.

Returns: int: \<0 on failure.

#### ev_insn_reads_tbit

```
ev_insn_reads_tbit(
    insn: 'insn_t const *',
    getreg: 'processor_t::regval_getter_t *',
    regvalues: regval_t,
) -> int

```

Check if insn will read the TF bit.

Args: insn (insn_t const *): The instruction. getreg (processor_t::regval_getter_t* ): Function to get register values. regvalues (regval_t): Register values array.

Returns: int: 2 if will generate 'step' exception, 1 if will store the TF bit in memory, 0 if no.

#### ev_is_addr_insn

```
ev_is_addr_insn(
    type: 'int *', insn: 'insn_t const *'
) -> int

```

Does the instruction calculate some address using an immediate operand?

For example, in PC, such operand may be o_displ: 'lea eax, [esi+4]'

Args: type (int *): Pointer to the returned instruction type. 0: "add" instruction (immediate operand is a relative value) 1: "move" instruction (immediate operand is absolute) 2: "sub" instruction (immediate operand is a relative value) insn (insn_t const* ): Instruction.

Returns: int: >0 for operand number + 1, 0 if not implemented.

#### ev_is_align_insn

```
ev_is_align_insn(ea: ea_t) -> int

```

Checks if the instruction is created only for alignment purposes.

Do not directly call this function, use is_align_insn().

Args: ea (ea_t): Instruction address.

Returns: int: Number of bytes in the instruction.

#### ev_is_alloca_probe

```
ev_is_alloca_probe(ea: ea_t) -> int

```

Checks if the function at 'ea' behaves as \_\_alloca_probe.

Args: ea (ea_t): Function address.

Returns: int: 1: Yes. 0: No.

#### ev_is_basic_block_end

```
ev_is_basic_block_end(
    insn: 'insn_t const *', call_insn_stops_block: bool
) -> int

```

Checks if the current instruction is the end of a basic block.

This function should be defined for processors with delayed jump slots.

Args: insn (insn_t const \*): The instruction. call_insn_stops_block (bool): True if call instruction stops block.

Returns: int: 0: Unknown. \<0: No, not the end. 1: Yes, is the end.

#### ev_is_call_insn

```
ev_is_call_insn(insn: 'insn_t const *') -> int

```

Checks if the instruction is a "call".

Args: insn (insn_t const \*): The instruction.

Returns: int: 0: Unknown. \<0: No, not a call. 1: Yes, is a call.

#### ev_is_cond_insn

```
ev_is_cond_insn(insn: 'insn_t const *') -> int

```

Checks if the instruction is conditional.

Args: insn (insn_t const \*): The instruction address.

Returns: int: 1: Yes, conditional instruction. -1: No, not conditional. 0: Not implemented or not an instruction.

#### ev_is_control_flow_guard

```
ev_is_control_flow_guard(
    p_reg: 'int *', insn: 'insn_t const *'
) -> int

```

Detect if an instruction is a "thunk call" to a flow guard function (equivalent to call reg/return/nop).

Args: p_reg (int *): Indirect register number, may be -1. insn (insn_t const* ): Call/jump instruction.

Returns: int: -1 if no thunk detected, 1 if indirect call, 2 if security check routine call (NOP), 3 if return thunk, 0 if not implemented.

#### ev_is_far_jump

```
ev_is_far_jump(icode: int) -> int

```

Checks if the instruction is an indirect far jump or call instruction. Meaningful only if the processor has 'near' and 'far' reference types.

Args: icode (int): Instruction code.

Returns: int: 0: Not implemented. 1: Yes, is a far jump/call. -1: No.

#### ev_is_indirect_jump

```
ev_is_indirect_jump(insn: 'insn_t const *') -> int

```

Determine if instruction is an indirect jump.

If CF_JUMP bit cannot describe all jump types, please define this callback.

Args: insn (insn_t const \*): The instruction.

Returns: int: 0: Use CF_JUMP. 1: No, not indirect jump. 2: Yes, is indirect jump.

#### ev_is_insn_table_jump

```
ev_is_insn_table_jump() -> int

```

Reserved.

#### ev_is_jump_func

```
ev_is_jump_func(
    pfn: 'func_t *',
    jump_target: 'ea_t *',
    func_pointer: 'ea_t *',
) -> int

```

Determine if the function is a trivial "jump" function.

Args: pfn (func_t *): The function. jump_target (ea_t* ): Out, jump target. func_pointer (ea_t \*): Out, function pointer.

Returns: int: \<0 if no, 0 if don't know, 1 if yes (see jump_target and func_pointer).

#### ev_is_ret_insn

```
ev_is_ret_insn(insn: 'insn_t const *', flags: uchar) -> int

```

Checks if the instruction is a "return".

Args: insn (insn_t const \*): The instruction. flags (uchar): Combination of IRI\_... flags.

Returns: int: 0: Unknown. \<0: No, not a return. 1: Yes, is a return.

#### ev_is_sane_insn

```
ev_is_sane_insn(
    insn: 'insn_t const *', no_crefs: int
) -> int

```

Checks if the instruction is sane for the current file type.

Args: insn (insn_t const \*): The instruction. no_crefs (int): 1 if the instruction has no code refs (IDA just tries to convert unexplored bytes to an instruction), 0 if created because of some coderef, user request or other weighty reason.

Returns: int:

> =0: OK (sane). \<0: No, the instruction isn't likely to appear in the program.

#### ev_is_sp_based

```
ev_is_sp_based(
    mode: 'int *',
    insn: 'insn_t const *',
    op: 'op_t const *',
) -> int

```

Check whether the operand is relative to stack pointer or frame pointer.

This event is used to determine how to output a stack variable. If not implemented, all operands are sp based by default. Implement this only if some stack references use frame pointer instead of stack pointer.

Args: mode (int *): Out, combination of SP/FP operand flags. insn (insn_t const* ): The instruction. op (op_t const \*): The operand.

Returns: int: 0 if not implemented, 1 if ok.

#### ev_is_switch

```
ev_is_switch(
    si: switch_info_t, insn: 'insn_t const *'
) -> int

```

Find 'switch' idiom or override processor module's decision.

Called for instructions marked with CF_JUMP.

Args: si (switch_info_t): Output, switch info. insn (insn_t const \*): Instruction possibly belonging to a switch.

Returns: int: 1: Switch is found, 'si' is filled. -1: No switch found. Forbids switch creation by processor module. 0: Not implemented.

#### ev_last_cb_before_loader

```
ev_last_cb_before_loader() -> int

```

#### ev_loader

```
ev_loader() -> int

```

This code and higher ones are reserved for the loaders. The arguments and the return values are defined by the loaders.

#### ev_lower_func_type

```
ev_lower_func_type(
    argnums: 'intvec_t *', fti: func_type_data_t
) -> int

```

Get function arguments to convert to pointers when lowering prototype.

The processor module can also modify 'fti' for non-standard conversions. argnums[0] can contain a special negative value indicating that the return value should be passed as a hidden 'retstr' argument:

- -1: first argument, return pointer to the argument
- -2: last argument, return pointer to the argument
- -3: first argument, return void

Args: argnums (intvec_t): Output, numbers of arguments to convert to pointers (ascending order). fti (func_type_data_t): Inout, function type details.

Returns: int: 0 if not implemented, 1 if argnums was filled, 2 if argnums was filled and fti substantially changed.

#### ev_max_ptr_size

```
ev_max_ptr_size() -> int

```

Get maximal size of a pointer in bytes.

Returns: int: Maximum possible size of a pointer.

#### ev_may_be_func

```
ev_may_be_func(insn: 'insn_t const *', state: int) -> int

```

Checks if a function can start at this instruction.

Args: insn (insn_t const \*): The instruction. state (int): Autoanalysis phase. 0 for creating functions, 1 for creating chunks.

Returns: int: Probability (1..100).

#### ev_may_show_sreg

```
ev_may_show_sreg(current_ea: ea_t) -> int

```

The kernel wants to display the segment registers in the messages window.

Args: current_ea (ea_t): Current address.

Returns: int: \<0 if the kernel should not show the segment registers (assuming the module has done it), 0 if not implemented.

#### ev_moving_segm

```
ev_moving_segm(
    seg: 'segment_t *', to: ea_t, flags: int
) -> int

```

May the kernel move the segment?

Args: seg (segment_t \*): Segment to move. to (ea_t): New segment start address. flags (int): Combination of Move segment flags.

Returns: int: 0 for yes, \<0 for the kernel should stop.

#### ev_newasm

```
ev_newasm(asmnum: int) -> int

```

Called before setting a new assembler.

Args: asmnum (int): The assembler number. See also ev_asm_installed.

#### ev_newbinary

```
ev_newbinary(
    filename: 'char *',
    fileoff: qoff64_t,
    basepara: ea_t,
    binoff: ea_t,
    nbytes: uint64,
) -> int

```

Called when IDA is about to load a binary file.

Args: filename (char \*): Binary file name. fileoff (qoff64_t): Offset in the file. basepara (ea_t): Base loading paragraph. binoff (ea_t): Loader offset. nbytes (uint64): Number of bytes to load.

#### ev_newfile

```
ev_newfile(fname: 'char *') -> int

```

Called when a new file has been loaded.

Args: fname (char \*): The input file name.

#### ev_newprc

```
ev_newprc(pnum: int, keep_cfg: bool) -> int

```

Called before changing processor type.

Args: pnum (int): Processor number in the array of processor names. keep_cfg (bool): True to not modify kernel configuration.

Returns: int: 1 if OK, \<0 to prohibit change.

#### ev_next_exec_insn

```
ev_next_exec_insn(
    target: 'ea_t *',
    ea: ea_t,
    tid: int,
    getreg: 'processor_t::regval_getter_t *',
    regvalues: regval_t,
) -> int

```

Get next address to be executed.

Must return the next address to be executed. If the instruction following the current one is executed, return BADADDR. Usually used for jumps, branches, calls, returns. This is essential if "single step" is not supported in hardware.

Args: target (ea_t *): Out: pointer to the answer. ea (ea_t): Instruction address. tid (int): Current thread id. getreg (processor_t::regval_getter_t* ): Function to get register values. regvalues (regval_t): Register values array (const).

Returns: int: 0 if unimplemented, 1 if implemented.

#### ev_oldfile

```
ev_oldfile(fname: 'char *') -> int

```

Called when an old file has been loaded.

Args: fname (char \*): The input file name.

#### ev_out_assumes

```
ev_out_assumes(outctx: 'outctx_t *') -> int

```

Produce assume directives when segment register value changes.

Args: outctx (outctx_t \*): Output context.

Returns: int: 1 if OK, 0 if not implemented.

#### ev_out_data

```
ev_out_data(
    outctx: 'outctx_t *', analyze_only: bool
) -> int

```

Generate text representation of data items.

This function may change the database and create cross-references if analyze_only is set.

Args: outctx (outctx_t \*): Output context. analyze_only (bool): True if only analysis should be performed.

Returns: int: 1 if OK, 0 if not implemented.

#### ev_out_footer

```
ev_out_footer(outctx: 'outctx_t *') -> int

```

Produce the end of disassembled text.

Args: outctx (outctx_t \*): Output context.

#### ev_out_header

```
ev_out_header(outctx: 'outctx_t *') -> int

```

Produce the start of disassembled text.

Args: outctx (outctx_t \*): Output context.

#### ev_out_insn

```
ev_out_insn(outctx: 'outctx_t *') -> bool

```

Generate text representation of an instruction in 'ctx.insn'.

outctx_t provides functions to output the generated text. This function shouldn't change the database, flags, or anything else. All these actions should be performed only by emu_insn().

Args: outctx (outctx_t \*): Output context.

#### ev_out_label

```
ev_out_label(
    outctx: 'outctx_t *', colored_name: str
) -> int

```

The kernel is going to generate an instruction label line or a function header.

Args: outctx (outctx_t \*): Output context. colored_name (str): Colored name string.

Returns: int: \<0 if the kernel should not generate the label, 0 if not implemented or continue.

#### ev_out_mnem

```
ev_out_mnem(outctx: 'outctx_t *') -> int

```

Generate instruction mnemonics.

This callback should append the colored mnemonics to ctx.outbuf. Optional notification; if absent, out_mnem will be called.

Args: outctx (outctx_t \*): Output context.

Returns: int: 1 if appended the mnemonics, 0 if not implemented.

#### ev_out_operand

```
ev_out_operand(
    outctx: 'outctx_t *', op: 'op_t const *'
) -> bool

```

Generate text representation of an instruction operand.

outctx_t provides functions to output the generated text. All these actions should be performed only by emu_insn().

Args: outctx (outctx_t *): Output context. op (op_t const* ): Operand.

Returns: bool: True (1) if OK, False (-1) if the operand is hidden.

#### ev_out_segend

```
ev_out_segend(
    outctx: 'outctx_t *', seg: 'segment_t *'
) -> int

```

Produce the end of a segment in disassembled output.

Args: outctx (outctx_t *): Output context. seg (segment_t* ): Segment.

Returns: int: 1 if OK, 0 if not implemented.

#### ev_out_segstart

```
ev_out_segstart(
    outctx: 'outctx_t *', seg: 'segment_t *'
) -> int

```

Produce the start of a segment in disassembled output.

Args: outctx (outctx_t *): Output context. seg (segment_t* ): Segment.

Returns: int: 1 if OK, 0 if not implemented.

#### ev_out_special_item

```
ev_out_special_item(
    outctx: 'outctx_t *', segtype: uchar
) -> int

```

Generate text representation of an item in a special segment.

Examples: absolute symbols, externs, communal definitions, etc.

Args: outctx (outctx_t \*): Output context. segtype (uchar): Segment type.

Returns: int: 1 if OK, 0 if not implemented, -1 on overflow.

#### ev_privrange_changed

```
ev_privrange_changed(
    old_privrange: range_t, delta: adiff_t
) -> int

```

Privrange interval has been moved to a new location. Most common actions: fix indices of netnodes used by module.

Args: old_privrange (range_t): Old privrange interval. delta (adiff_t): Address difference.

Returns: int: 0 for Ok, -1 for error (and message in errbuf).

#### ev_realcvt

```
ev_realcvt(
    m: 'void *', e: 'fpvalue_t *', swt: uint16
) -> int

```

Floating point to IEEE conversion.

Args: m (void *): Pointer to processor-specific floating point value. e (fpvalue_t* ): IDA representation of a floating point value. swt (uint16): Operation (see realcvt() in ieee.h).

Returns: int: 0 if not implemented.

#### ev_rename

```
ev_rename(ea: ea_t, new_name: str) -> int

```

The kernel is going to rename a byte.

Args: ea (ea_t): Address of the item to rename. new_name (str): New name to assign.

Returns: int: \<0: If the kernel should not rename it. 2: To inhibit the notification. The kernel should not rename, but 'set_name()' should return 'true'. (Also see 'renamed'.) The return value is ignored when kernel is going to delete name.

#### ev_replaying_undo

```
ev_replaying_undo(
    action_name: str,
    vec: 'undo_records_t const *',
    is_undo: bool,
) -> int

```

Replaying an undo/redo buffer.

Args: action_name (str): Action being undone or redone (can be None for intermediary buffers). vec (undo_records_t const \*): Undo records vector. is_undo (bool): True if undo, False if redo.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_set_code16_mode

```
ev_set_code16_mode(ea: ea_t, code16: bool) -> int

```

Set ISA 16-bit mode (for some processors, e.g. ARM Thumb, PPC VLE, MIPS16).

Args: ea (ea_t): Address to set new ISA mode. code16 (bool): True for 16-bit mode, False for 32-bit mode.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_set_proc_options

```
ev_set_proc_options(options: str, confidence: int) -> int

```

Called if the user specified an option string in the command line or via SetProcessorType.

Can be used for setting a processor subtype. Also called if option string is passed to set_processor_type() and IDC's SetProcessorType().

Args: options (str): Option string (e.g., processor subtype). confidence (int): 0 for loader's suggestion, 1 for user's decision.

Returns: int: \<0 if bad option string.

#### ev_setup_til

```
ev_setup_til() -> int

```

Setup default type libraries.

Called after loading a new file into the database. The processor module may load TILs, setup memory model, and perform other actions required to set up the type system. This is an optional callback.

Returns: int: 1 if ok, 0 if not implemented.

#### ev_str2reg

```
ev_str2reg(regname: str) -> int

```

Convert a register name to a register number.

The register number is the register index in the processor_t::reg_names array. Most processor modules do not need to implement this callback; useful only if processor_t::reg_names[reg] does not provide the correct register names.

Args: regname (str): Register name.

Returns: int: Register number + 1, 0 if not implemented or could not be decoded.

#### ev_term

```
ev_term() -> int

```

The IDP module is being unloaded.

#### ev_treat_hindering_item

```
ev_treat_hindering_item(
    hindering_item_ea: ea_t,
    new_item_flags: flags64_t,
    new_item_ea: ea_t,
    new_item_length: asize_t,
) -> int

```

An item hinders creation of another item.

Args: hindering_item_ea (ea_t): Address of the hindering item. new_item_flags (flags64_t): Flags for the new item (0 for code). new_item_ea (ea_t): Address of the new item. new_item_length (asize_t): Length of the new item.

Returns: int: 0 for no reaction, !=0 if the kernel may delete the hindering item.

#### ev_undefine

```
ev_undefine(ea: ea_t) -> int

```

An item in the database (instruction or data) is being deleted.

Args: ea (ea_t): Address.

Returns: int: 1 to not delete srranges at the item end, 0 to allow srranges to be deleted.

#### ev_update_call_stack

```
ev_update_call_stack(
    stack: call_stack_t,
    tid: int,
    getreg: 'processor_t::regval_getter_t *',
    regvalues: regval_t,
) -> int

```

Calculate the call stack trace for the given thread.

This callback is invoked when the process is suspended and should fill the 'trace' object with the information about the current call stack. Note that this callback is NOT invoked if the current debugger backend implements stack tracing via debugger_t::event_t::ev_update_call_stack. The debugger-specific algorithm takes priority. Implementing this callback in the processor module is useful when multiple debugging platforms follow similar patterns, and thus the same processor-specific algorithm can be used for different platforms.

Args: stack (call_stack_t): Result object to fill with call stack trace. tid (int): Thread ID. getreg (processor_t::regval_getter_t \*): Function to get register values. regvalues (regval_t): Register values array.

Returns: int: 1 if ok, -1 if failed, 0 if unimplemented.

#### ev_use_arg_types

```
ev_use_arg_types(
    ea: ea_t, fti: func_type_data_t, rargs: 'funcargvec_t *'
) -> int

```

Use information about callee arguments.

Args: ea (ea_t): Address of the call instruction. fti (func_type_data_t): Function type info. rargs (funcargvec_t): Array of register arguments.

Returns: int: 1 if handled (removes handled args from fti/rargs), 0 if not implemented.

#### ev_use_regarg_type

```
ev_use_regarg_type(
    ea: ea_t, rargs: 'funcargvec_t const *'
) -> 'PyObject *'

```

Use information about register argument.

Args: ea (ea_t): Address of the instruction. rargs (funcargvec_t): Vector of register arguments.

Returns: PyObject\*: 1 if ok, 0 if not implemented.

#### ev_use_stkarg_type

```
ev_use_stkarg_type(ea: ea_t, arg: funcarg_t) -> int

```

Use information about a stack argument.

Args: ea (ea_t): Address of the push instruction which pushes the argument onto the stack. arg (funcarg_t): Argument information.

Returns: int: 1 if ok, \<=0 if failed (kernel will create a comment for the instruction).

#### ev_validate_flirt_func

```
ev_validate_flirt_func(
    start_ea: ea_t, funcname: str
) -> int

```

FLIRT has recognized a library function. This callback can be used by a plugin or proc module to intercept and validate such a function.

Args: start_ea (ea_t): Function start address. funcname (str): Recognized function name.

Returns: int: -1 to not create a function, 0 if function is validated.

#### ev_verify_noreturn

```
ev_verify_noreturn(pfn: 'func_t *') -> int

```

The kernel wants to set 'noreturn' flags for a function.

Args: pfn (func_t \*): The function.

Returns: int: 0 if ok, any other value means do not set 'noreturn' flag.

#### ev_verify_sp

```
ev_verify_sp(pfn: 'func_t *') -> int

```

Called after all function instructions have been analyzed.

Now the processor module can analyze the stack pointer for the whole function.

Args: pfn (func_t \*): The function.

Returns: int: 0 if ok, \<0 if bad stack pointer.

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

### UIHooks

```
UIHooks()

```

Bases: `_BaseHooks`, `UI_Hooks`

Convenience class for UI events handling.

Methods:

- **`create_desktop_widget`** – Create a widget to be placed in the widget tree (at desktop-creation time).
- **`current_widget_changed`** – Called when the currently-active TWidget has changed.
- **`database_closed`** – The database has been closed.
- **`database_inited`** – Called when database initialization has completed and the kernel is about to run IDC
- **`debugger_menu_change`** – Notifies about debugger menu modification.
- **`desktop_applied`** – Called when a desktop has been applied.
- **`destroying_plugmod`** – Called when the plugin object is about to be destroyed.
- **`destroying_procmod`** – Called when the processor module is about to be destroyed.
- **`finish_populating_widget_popup`** – Called when IDA is about to be done populating the context menu for a widget.
- **`get_chooser_item_attrs`** – Get item-specific attributes for a chooser.
- **`get_custom_viewer_hint`** – Requests a hint for a viewer (idaview or custom).
- **`get_ea_hint`** – Requests a simple hint for an address. Use this event to generate a custom hint.
- **`get_item_hint`** – Requests a multiline hint for an item.
- **`get_lines_rendering_info`** – Get lines rendering information.
- **`get_widget_config`** – Retrieve the widget configuration.
- **`hook`** – Hook (activate) the event handlers.
- **`idcstart`** – Start of IDC engine work.
- **`idcstop`** – Stop of IDC engine work.
- **`initing_database`** – Called when database initialization has started.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`plugin_loaded`** – Called when a plugin has been loaded in memory.
- **`plugin_unloading`** – Called when a plugin is about to be unloaded.
- **`populating_widget_popup`** – Called when IDA is populating the context menu for a widget.
- **`postprocess_action`** – Called after an IDA UI action has been handled.
- **`preprocess_action`** – Called when the IDA UI is about to handle a user action.
- **`range`** – The disassembly range has been changed (idainfo::min_ea ... idainfo::max_ea).
- **`ready_to_run`** – Called when all UI elements have been initialized.
- **`resume`** – Resume the suspended graphical interface. Only the text version.
- **`saved`** – The kernel has saved the database. This callback just informs the interface.
- **`saving`** – The kernel is flushing its buffers to the disk.
- **`screen_ea_changed`** – Called when the "current address" has changed.
- **`set_widget_config`** – Set the widget configuration.
- **`suspend`** – Suspend graphical interface. Only the text version.
- **`unhook`** – Un-hook (de-activate) the event handlers.
- **`updated_actions`** – Called when IDA is done updating actions.
- **`updating_actions`** – Called when IDA is about to update all actions.
- **`widget_closing`** – Called when a TWidget is about to close. This event precedes ui_widget_invisible.
- **`widget_invisible`** – Called when a TWidget is being closed. Use this event to destroy the window controls.
- **`widget_visible`** – Called when a TWidget is displayed on the screen.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### create_desktop_widget

```
create_desktop_widget(
    title: str, cfg: jobj_wrapper_t
) -> 'PyObject *'

```

Create a widget to be placed in the widget tree (at desktop-creation time).

Args: title (str): The widget title. cfg (jobj_t): Configuration object.

Returns: PyObject\*: The created widget, or None.

#### current_widget_changed

```
current_widget_changed(
    widget: 'TWidget *', prev_widget: 'TWidget *'
) -> None

```

Called when the currently-active TWidget has changed.

Args: widget (TWidget\*): The new active widget. prev_widget (TWidget\*): The previously active widget.

#### database_closed

```
database_closed() -> None

```

The database has been closed. See also processor_t::closebase, it occurs earlier. See also ui_initing_database. This is not the same as IDA exiting. If you need to perform cleanup at the exiting time, use qatexit().

#### database_inited

```
database_inited(
    is_new_database: int, idc_script: str
) -> None

```

Called when database initialization has completed and the kernel is about to run IDC scripts.

Args: is_new_database (int): Non-zero if the database is new. idc_script (str): The IDC script to run (may be None).

Note: See also ui_initing_database. This event is called for both new and old databases.

#### debugger_menu_change

```
debugger_menu_change(enable: bool) -> None

```

Notifies about debugger menu modification. Args: enable (bool): True if the debugger menu has been added or a different debugger has been selected. False if the debugger menu will be removed (user switched to "No debugger").

#### desktop_applied

```
desktop_applied(
    name: str, from_idb: bool, type: int
) -> None

```

Called when a desktop has been applied.

Args: name (str): The desktop name. from_idb (bool): True if the desktop was stored in the IDB, False if it comes from the registry. type (int): The desktop type (1-disassembly, 2-debugger, 3-merge).

#### destroying_plugmod

```
destroying_plugmod(
    plugmod: plugmod_t, entry: 'plugin_t const *'
) -> None

```

Called when the plugin object is about to be destroyed.

Args: plugmod (plugmod_t): The plugin object being destroyed. entry (plugin_t const \*): Plugin entry.

#### destroying_procmod

```
destroying_procmod(procmod: procmod_t) -> None

```

Called when the processor module is about to be destroyed.

Args: procmod (procmod_t): The processor module being destroyed.

#### finish_populating_widget_popup

```
finish_populating_widget_popup(
    widget: 'TWidget *',
    popup_handle: 'TPopupMenu *',
    ctx: action_ctx_base_t = None,
) -> None

```

Called when IDA is about to be done populating the context menu for a widget.

This is your chance to attach_action_to_popup().

Args: widget (TWidget\*): The widget for which the popup is being finalized. popup_handle (TPopupMenu\*): The popup menu handle. ctx (action_activation_ctx_t, optional): The action context.

#### get_chooser_item_attrs

```
get_chooser_item_attrs(
    chooser: chooser_base_t,
    n: size_t,
    attrs: chooser_item_attrs_t,
) -> None

```

Get item-specific attributes for a chooser.

This callback is generated only after enable_chooser_attrs().

Args: chooser (chooser_base_t): The chooser object. n (size_t): Index of the item. attrs (chooser_item_attrs_t): Attributes to be set.

#### get_custom_viewer_hint

```
get_custom_viewer_hint(
    viewer: 'TWidget *', place: place_t
) -> 'PyObject *'

```

Requests a hint for a viewer (idaview or custom).

Each subscriber should append their hint lines to HINT and increment IMPORTANT_LINES accordingly. Completely overwriting the existing lines in HINT is possible but not recommended.

If the REG_HINTS_MARKER sequence is found in the returned hints string, it will be replaced with the contents of the "regular" hints. If the SRCDBG_HINTS_MARKER sequence is found, it will be replaced with the contents of the source-level debugger-generated hints.

Special keywords:

- HIGHLIGHT text: Where 'text' will be highlighted.
- CAPTION caption: Caption for the hint widget.

Args: viewer (TWidget\*): The viewer widget. place (place_t\*): The current position in the viewer.

Returns: PyObject\*: 0 to continue collecting hints from other subscribers, 1 to stop collecting hints.

#### get_ea_hint

```
get_ea_hint(ea: ea_t) -> 'PyObject *'

```

Requests a simple hint for an address. Use this event to generate a custom hint. See also: more generic ui_get_item_hint. Args: ea (ea_t): The address for which the hint is requested. Returns: PyObject\*: True if a hint was generated.

#### get_item_hint

```
get_item_hint(ea: ea_t, max_lines: int) -> 'PyObject *'

```

Requests a multiline hint for an item. See also: more generic ui_get_custom_viewer_hint. Args: ea (ea_t): Address or item id (e.g., structure or enum member). max_lines (int): Maximum number of lines to show. Returns: PyObject\*: True if a hint was generated.

#### get_lines_rendering_info

```
get_lines_rendering_info(
    out: lines_rendering_output_t,
    widget: 'TWidget const *',
    info: lines_rendering_input_t,
) -> None

```

Get lines rendering information.

Args: out (lines_rendering_output_t): Output information to be populated. widget (TWidget const\*): The widget for which rendering info is requested. info (lines_rendering_input_t): Input rendering information.

#### get_widget_config

```
get_widget_config(
    widget: 'TWidget const *', cfg: 'jobj_t *'
) -> 'PyObject *'

```

Retrieve the widget configuration.

This configuration will be passed back at `ui_create_desktop_widget` and `ui_set_widget_config` time.

Args: widget (TWidget const *): The widget to retrieve configuration for. cfg (jobj_t* ): Configuration object.

Returns: PyObject\*: The widget configuration.

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### idcstart

```
idcstart() -> None

```

Start of IDC engine work.

#### idcstop

```
idcstop() -> None

```

Stop of IDC engine work.

#### initing_database

```
initing_database() -> None

```

Called when database initialization has started.

See also: `ui_database_inited`. This event is called for both new and old databases.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### plugin_loaded

```
plugin_loaded(plugin_info: 'plugin_info_t const *') -> None

```

Called when a plugin has been loaded in memory.

Args: plugin_info (plugin_info_t const\*): Information about the loaded plugin.

#### plugin_unloading

```
plugin_unloading(
    plugin_info: 'plugin_info_t const *',
) -> None

```

Called when a plugin is about to be unloaded.

Args: plugin_info (plugin_info_t const\*): Information about the plugin being unloaded.

#### populating_widget_popup

```
populating_widget_popup(
    widget: 'TWidget *',
    popup_handle: 'TPopupMenu *',
    ctx: action_ctx_base_t = None,
) -> None

```

Called when IDA is populating the context menu for a widget.

This is your chance to attach_action_to_popup(). See also `ui_finish_populating_widget_popup` if you want to augment the context menu with your own actions after the menu has been properly populated by the owning component or plugin (which typically does it on ui_populating_widget_popup).

Args: widget (TWidget *): The widget for which the popup is being populated. popup_handle (TPopupMenu* ): The popup menu handle. ctx (action_activation_ctx_t, optional): The action context.

#### postprocess_action

```
postprocess_action() -> None

```

Called after an IDA UI action has been handled.

#### preprocess_action

```
preprocess_action(name: str) -> int

```

Called when the IDA UI is about to handle a user action.

Args: name (str): UI action name. These names can be looked up in ida[tg]ui.cfg.

Returns: int: 0 if OK, nonzero if a plugin has handled the command.

#### range

```
range() -> None

```

The disassembly range has been changed (idainfo::min_ea ... idainfo::max_ea). UI should redraw the scrollbars. See also: ui_lock_range_refresh.

#### ready_to_run

```
ready_to_run() -> None

```

Called when all UI elements have been initialized.

Automatic plugins may hook to this event to perform their tasks.

#### resume

```
resume() -> None

```

Resume the suspended graphical interface. Only the text version. Interface should respond to it.

#### saved

```
saved(path: str) -> None

```

The kernel has saved the database. This callback just informs the interface. Note that at the time this notification is sent, the internal paths are not updated yet, and calling get_path(PATH_TYPE_IDB) will return the previous path. Args: path (str): The database path.

#### saving

```
saving() -> None

```

The kernel is flushing its buffers to the disk. The user interface should save its state.

#### screen_ea_changed

```
screen_ea_changed(ea: ea_t, prev_ea: ea_t) -> None

```

Called when the "current address" has changed.

Args: ea (ea_t): The new address. prev_ea (ea_t): The previous address.

#### set_widget_config

```
set_widget_config(
    widget: 'TWidget const *', cfg: jobj_wrapper_t
) -> None

```

Set the widget configuration.

Args: widget (TWidget const \*): The widget to configure. cfg (jobj_t): Configuration object.

#### suspend

```
suspend() -> None

```

Suspend graphical interface. Only the text version. Interface should respond to it.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

#### updated_actions

```
updated_actions() -> None

```

Called when IDA is done updating actions.

#### updating_actions

```
updating_actions(ctx: action_ctx_base_t) -> None

```

Called when IDA is about to update all actions.

If your plugin needs to perform expensive operations more than once (e.g., once per action it registers), you should do them only once, right away.

Args: ctx (action_update_ctx_t): The update context.

#### widget_closing

```
widget_closing(widget: 'TWidget *') -> None

```

Called when a TWidget is about to close. This event precedes ui_widget_invisible. Use this to perform any actions relevant to the lifecycle of this widget. Args: widget (TWidget\*): The widget that is about to close.

#### widget_invisible

```
widget_invisible(widget: 'TWidget *') -> None

```

Called when a TWidget is being closed. Use this event to destroy the window controls. Args: widget (TWidget\*): The widget that became invisible.

#### widget_visible

```
widget_visible(widget: 'TWidget *') -> None

```

Called when a TWidget is displayed on the screen. Use this event to populate the window with controls. Args: widget (TWidget\*): The widget that became visible.

### ViewHooks

```
ViewHooks()

```

Bases: `_BaseHooks`, `View_Hooks`

Convenience class for IDA View events handling.

Methods:

- **`hook`** – Hook (activate) the event handlers.
- **`log`** – Utility method to optionally log called hooks and their parameters.
- **`unhook`** – Un-hook (de-activate) the event handlers.
- **`view_activated`** – Called when a view is activated.
- **`view_click`** – Called when a click event occurs in the view.
- **`view_close`** – Called when a view is closed.
- **`view_created`** – Called when a view is created.
- **`view_curpos`** – Called when the cursor position in a view changes.
- **`view_dblclick`** – Called when a double-click event occurs in the view.
- **`view_deactivated`** – Called when a view is deactivated.
- **`view_keydown`** – Called when a key down event occurs in the view.
- **`view_loc_changed`** – Called when the location for the view has changed.
- **`view_mouse_moved`** – Called when the mouse moved in the view.
- **`view_mouse_over`** – Called when the mouse moves over (or out of) a node or an edge.
- **`view_switched`** – Called when a view's renderer has changed.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`is_hooked`** (`bool`) –
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### is_hooked

```
is_hooked: bool

```

#### m_database

```
m_database = database

```

#### hook

```
hook() -> None

```

Hook (activate) the event handlers.

#### log

```
log(msg: str = '') -> None

```

Utility method to optionally log called hooks and their parameters.

#### unhook

```
unhook() -> None

```

Un-hook (de-activate) the event handlers.

#### view_activated

```
view_activated(view: 'TWidget *') -> None

```

Called when a view is activated. Args: view (TWidget \*): The activated view.

#### view_click

```
view_click(
    view: 'TWidget *', event: view_mouse_event_t
) -> None

```

Called when a click event occurs in the view. Args: view (TWidget \*): The view where the click occurred. event (view_mouse_event_t): The mouse event information.

#### view_close

```
view_close(view: 'TWidget *') -> None

```

Called when a view is closed. Args: view (TWidget \*): The closed view.

#### view_created

```
view_created(view: 'TWidget *') -> None

```

Called when a view is created. Args: view (TWidget \*): The created view.

#### view_curpos

```
view_curpos(view: 'TWidget *') -> None

```

Called when the cursor position in a view changes. Args: view (TWidget \*): The view whose cursor position changed.

#### view_dblclick

```
view_dblclick(
    view: 'TWidget *', event: view_mouse_event_t
) -> None

```

Called when a double-click event occurs in the view. Args: view (TWidget \*): The view where the double-click occurred. event (view_mouse_event_t): The mouse event information.

#### view_deactivated

```
view_deactivated(view: 'TWidget *') -> None

```

Called when a view is deactivated. Args: view (TWidget \*): The deactivated view.

#### view_keydown

```
view_keydown(
    view: 'TWidget *', key: int, state: view_event_state_t
) -> None

```

Called when a key down event occurs in the view. Args: view (TWidget \*): The view receiving the key event. key (int): The key code. state (view_event_state_t): The event state.

#### view_loc_changed

```
view_loc_changed(
    view: 'TWidget *',
    now: 'lochist_entry_t const *',
    was: 'lochist_entry_t const *',
) -> None

```

Called when the location for the view has changed. (Can be either the place_t, the renderer_info_t, or both.) Args: view (TWidget *): The view whose location changed. now (lochist_entry_t const* ): The new location. was (lochist_entry_t const \*): The previous location.

#### view_mouse_moved

```
view_mouse_moved(
    view: 'TWidget *', event: view_mouse_event_t
) -> None

```

Called when the mouse moved in the view. Args: view (TWidget \*): The view where the mouse moved. event (view_mouse_event_t): The mouse event information.

#### view_mouse_over

```
view_mouse_over(
    view: 'TWidget *', event: view_mouse_event_t
) -> None

```

Called when the mouse moves over (or out of) a node or an edge. This is only relevant in a graph view. Args: view (TWidget \*): The graph view. event (view_mouse_event_t): The mouse event information.

#### view_switched

```
view_switched(
    view: 'TWidget *', rt: tcc_renderer_type_t
) -> None

```

Called when a view's renderer has changed. Args: view (TWidget \*): The view that was switched. rt (tcc_renderer_type_t): The new renderer type.

# `Instructions`

## instructions

Classes:

- **`Instructions`** – Provides access to instruction-related operations using structured operand hierarchy.

### Instructions

```
Instructions(database: Database)

```

Bases: `DatabaseEntity`

Provides access to instruction-related operations using structured operand hierarchy.

Can be used to iterate over all instructions in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`breaks_sequential_flow`** – Check if the instruction stops sequential control flow.
- **`get_all`** – Retrieves an iterator over all instructions in the database.
- **`get_at`** – Decodes the instruction at the specified address.
- **`get_between`** – Retrieves instructions between the specified addresses.
- **`get_disassembly`** – Retrieves the disassembled string representation of the given instruction.
- **`get_mnemonic`** – Retrieves the mnemonic of the given instruction.
- **`get_operand`** – Get a specific operand from the instruction.
- **`get_operands`** – Get all operands from the instruction.
- **`get_operands_count`** – Retrieve the operands number of the given instruction.
- **`get_previous`** – Decodes previous instruction of the one at specified address.
- **`is_call_instruction`** – Check if the instruction is a call instruction.
- **`is_indirect_jump_or_call`** – Check if the instruction passes execution using indirect jump or call
- **`is_valid`** – Checks if the given instruction is valid.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### breaks_sequential_flow

```
breaks_sequential_flow(insn: insn_t) -> bool

```

Check if the instruction stops sequential control flow.

This includes return instructions, unconditional jumps, halt instructions, and any other instruction that doesn't pass execution to the next sequential instruction.

Args: insn: The instruction to analyze.

Returns: True if this instruction has the CF_STOP flag set.

#### get_all

```
get_all() -> Iterator[insn_t]

```

Retrieves an iterator over all instructions in the database.

Returns: An iterator over the instructions.

#### get_at

```
get_at(ea: ea_t) -> Optional[insn_t]

```

Decodes the instruction at the specified address.

Args: ea: The effective address of the instruction.

Returns: An insn_t instance, if fails returns None.

Raises: InvalidEAError: If the effective address is invalid.

#### get_between

```
get_between(start: ea_t, end: ea_t) -> Iterator[insn_t]

```

Retrieves instructions between the specified addresses.

Args: start: Start of the address range. end: End of the address range.

Returns: An instruction iterator.

Raises: InvalidEAError: If start or end are not within database bounds. InvalidParameterError: If start >= end.

#### get_disassembly

```
get_disassembly(
    insn: insn_t, remove_tags: bool = True
) -> Optional[str]

```

Retrieves the disassembled string representation of the given instruction.

Args: insn: The instruction to disassemble. remove_tags: If True, removes IDA color/formatting tags from the output.

Returns: The disassembly as string, if fails, returns None.

#### get_mnemonic

```
get_mnemonic(insn: insn_t) -> Optional[str]

```

Retrieves the mnemonic of the given instruction.

Args: insn: The instruction to analyze.

Returns: A string representing the mnemonic of the given instruction. If retrieving fails, returns None.

#### get_operand

```
get_operand(
    insn: insn_t, index: int
) -> Optional[Operand] | None

```

Get a specific operand from the instruction.

Args: insn: The instruction to analyze. index: The operand index (0, 1, 2, etc.).

Returns: An Operand instance of the appropriate type, or None if the index is invalid or operand is void.

#### get_operands

```
get_operands(insn: insn_t) -> List[Operand]

```

Get all operands from the instruction.

Args: insn: The instruction to analyze.

Returns: A list of Operand instances of appropriate types (excludes void operands).

#### get_operands_count

```
get_operands_count(insn: insn_t) -> int

```

Retrieve the operands number of the given instruction.

Args: insn: The instruction to analyze.

Returns: An integer representing the number, if error, the number is negative.

#### get_previous

```
get_previous(ea: ea_t) -> Optional[insn_t]

```

Decodes previous instruction of the one at specified address.

Args: ea: The effective address of the instruction.

Returns: An insn_t instance, if fails returns None.

Raises: InvalidEAError: If the effective address is invalid.

#### is_call_instruction

```
is_call_instruction(insn: insn_t) -> bool

```

Check if the instruction is a call instruction.

Args: insn: The instruction to analyze.

Returns: True if this is a call instruction.

#### is_indirect_jump_or_call

```
is_indirect_jump_or_call(insn: insn_t) -> bool

```

Check if the instruction passes execution using indirect jump or call

Args: insn: The instruction to analyze. Returns: True if this instruction has the CF_JUMP flag set.

#### is_valid

```
is_valid(insn: insn_t) -> bool

```

Checks if the given instruction is valid.

Args: insn: The instruction to validate.

Returns: `True` if the instruction is valid, `False` otherwise.

# `Names`

## names

Classes:

- **`DemangleFlags`** – Flags for demangling operations.
- **`Names`** – Provides access to symbol and label management in the IDA database.
- **`SetNameFlags`** – Flags for set_name() function.

### DemangleFlags

Bases: `IntFlag`

Flags for demangling operations.

Attributes:

- **`CALC_VALID`** –
- **`COMPILER_MSK`** –
- **`DEFFAR`** –
- **`DEFHUGE`** –
- **`DEFNEAR`** –
- **`DEFNEARANY`** –
- **`DEFNONE`** –
- **`DEFPTR64`** –
- **`DROP_IMP`** –
- **`IGN_ANYWAY`** –
- **`IGN_JMP`** –
- **`LONG_FORM`** –
- **`MOVE_JMP`** –
- **`NOBASEDT`** –
- **`NOCALLC`** –
- **`NOCLOSUR`** –
- **`NOCSVOL`** –
- **`NODEFINIT`** –
- **`NOECSU`** –
- **`NOMANAGE`** –
- **`NOMODULE`** –
- **`NOPOSTFC`** –
- **`NOPTRTYP`** –
- **`NOPTRTYP16`** –
- **`NORETTYPE`** –
- **`NOSCTYP`** –
- **`NOSTVIR`** –
- **`NOTHROW`** –
- **`NOTYPE`** –
- **`NOUNALG`** –
- **`NOUNDERSCORE`** –
- **`PTRMSK`** –
- **`SHORT_FORM`** –
- **`SHORT_S`** –
- **`SHORT_U`** –
- **`ZPT_SPACE`** –

#### CALC_VALID

```
CALC_VALID = MNG_CALC_VALID

```

#### COMPILER_MSK

```
COMPILER_MSK = MNG_COMPILER_MSK

```

#### DEFFAR

```
DEFFAR = MNG_DEFFAR

```

#### DEFHUGE

```
DEFHUGE = MNG_DEFHUGE

```

#### DEFNEAR

```
DEFNEAR = MNG_DEFNEAR

```

#### DEFNEARANY

```
DEFNEARANY = MNG_DEFNEARANY

```

#### DEFNONE

```
DEFNONE = MNG_DEFNONE

```

#### DEFPTR64

```
DEFPTR64 = MNG_DEFPTR64

```

#### DROP_IMP

```
DROP_IMP = MNG_DROP_IMP

```

#### IGN_ANYWAY

```
IGN_ANYWAY = MNG_IGN_ANYWAY

```

#### IGN_JMP

```
IGN_JMP = MNG_IGN_JMP

```

#### LONG_FORM

```
LONG_FORM = MNG_LONG_FORM

```

#### MOVE_JMP

```
MOVE_JMP = MNG_MOVE_JMP

```

#### NOBASEDT

```
NOBASEDT = MNG_NOBASEDT

```

#### NOCALLC

```
NOCALLC = MNG_NOCALLC

```

#### NOCLOSUR

```
NOCLOSUR = MNG_NOCLOSUR

```

#### NOCSVOL

```
NOCSVOL = MNG_NOCSVOL

```

#### NODEFINIT

```
NODEFINIT = MNG_NODEFINIT

```

#### NOECSU

```
NOECSU = MNG_NOECSU

```

#### NOMANAGE

```
NOMANAGE = MNG_NOMANAGE

```

#### NOMODULE

```
NOMODULE = MNG_NOMODULE

```

#### NOPOSTFC

```
NOPOSTFC = MNG_NOPOSTFC

```

#### NOPTRTYP

```
NOPTRTYP = MNG_NOPTRTYP

```

#### NOPTRTYP16

```
NOPTRTYP16 = MNG_NOPTRTYP16

```

#### NORETTYPE

```
NORETTYPE = MNG_NORETTYPE

```

#### NOSCTYP

```
NOSCTYP = MNG_NOSCTYP

```

#### NOSTVIR

```
NOSTVIR = MNG_NOSTVIR

```

#### NOTHROW

```
NOTHROW = MNG_NOTHROW

```

#### NOTYPE

```
NOTYPE = MNG_NOTYPE

```

#### NOUNALG

```
NOUNALG = MNG_NOUNALG

```

#### NOUNDERSCORE

```
NOUNDERSCORE = MNG_NOUNDERSCORE

```

#### PTRMSK

```
PTRMSK = MNG_PTRMSK

```

#### SHORT_FORM

```
SHORT_FORM = MNG_SHORT_FORM

```

#### SHORT_S

```
SHORT_S = MNG_SHORT_S

```

#### SHORT_U

```
SHORT_U = MNG_SHORT_U

```

#### ZPT_SPACE

```
ZPT_SPACE = MNG_ZPT_SPACE

```

### Names

```
Names(database: Database)

```

Bases: `DatabaseEntity`

Provides access to symbol and label management in the IDA database.

Can be used to iterate over all names in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`delete`** – Delete name at the specified address.
- **`demangle_name`** – Demangle a mangled name.
- **`force_name`** – Force set a name, trying variations if the name already exists.
- **`get_all`** – Returns an iterator over all named elements in the database.
- **`get_at`** – Retrieves the name at the specified address.
- **`get_at_index`** – Retrieves the named element at the specified index.
- **`get_count`** – Retrieves the total number of named elements in the database.
- **`get_demangled_name`** – Get demangled name at address.
- **`is_public_name`** – Check if name at address is public.
- **`is_valid_name`** – Check if a name is a valid user defined name.
- **`is_weak_name`** – Check if name at address is weak.
- **`make_name_non_public`** – Make name at address non-public.
- **`make_name_non_weak`** – Make name at address non-weak.
- **`make_name_public`** – Make name at address public.
- **`make_name_weak`** – Make name at address weak.
- **`set_name`** – Set or delete name of an item at the specified address.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### delete

```
delete(ea: ea_t) -> bool

```

Delete name at the specified address.

Args: ea: Linear address.

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### demangle_name

```
demangle_name(
    name: str, disable_mask: Union[int, DemangleFlags] = 0
) -> str

```

Demangle a mangled name.

Args: name: Mangled name to demangle. disable_mask: Bits to inhibit parts of demangled name (DemangleFlags enum or raw int).

Returns: Demangled name or original name if demangling failed.

#### force_name

```
force_name(
    ea: ea_t,
    name: str,
    flags: Union[int, SetNameFlags] = NOCHECK,
) -> bool

```

Force set a name, trying variations if the name already exists.

Args: ea: Linear address. name: New name. flags: Set name flags (SetNameFlags enum or raw int).

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### get_all

```
get_all() -> Iterator[Tuple[ea_t, str]]

```

Returns an iterator over all named elements in the database.

Returns: An iterator over (address, name) tuples.

#### get_at

```
get_at(ea: ea_t) -> Optional[str]

```

Retrieves the name at the specified address.

Args: ea: The effective address.

Returns: The name string if it exists, None otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### get_at_index

```
get_at_index(index: int) -> Tuple[ea_t, str] | None

```

Retrieves the named element at the specified index.

Args: index: Index of the named element to retrieve.

Returns: A tuple (effective address, name) at the given index. In case of error, returns None.

#### get_count

```
get_count() -> int

```

Retrieves the total number of named elements in the database.

Returns: The number of named elements.

#### get_demangled_name

```
get_demangled_name(
    ea: ea_t,
    inhibitor: Union[int, DemangleFlags] = 0,
    demform: int = 0,
) -> Optional[str]

```

Get demangled name at address.

Args: ea: Linear address. inhibitor: Demangling inhibitor flags (DemangleFlags enum or raw int). demform: Demangling form flags.

Returns: Demangled name or None if not available.

Raises: InvalidEAError: If the effective address is invalid.

#### is_public_name

```
is_public_name(ea: ea_t) -> bool

```

Check if name at address is public.

Args: ea: Linear address.

Returns: True if public, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### is_valid_name

```
is_valid_name(name: str) -> bool

```

Check if a name is a valid user defined name.

Args: name: Name to validate.

Returns: True if valid, False otherwise.

#### is_weak_name

```
is_weak_name(ea: ea_t) -> bool

```

Check if name at address is weak.

Args: ea: Linear address.

Returns: True if weak, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### make_name_non_public

```
make_name_non_public(ea: ea_t) -> None

```

Make name at address non-public.

Args: ea: Linear address.

Raises: InvalidEAError: If the effective address is invalid.

#### make_name_non_weak

```
make_name_non_weak(ea: ea_t) -> None

```

Make name at address non-weak.

Args: ea: Linear address.

Raises: InvalidEAError: If the effective address is invalid.

#### make_name_public

```
make_name_public(ea: ea_t) -> None

```

Make name at address public.

Args: ea: Linear address.

Raises: InvalidEAError: If the effective address is invalid.

#### make_name_weak

```
make_name_weak(ea: ea_t) -> None

```

Make name at address weak.

Args: ea: Linear address.

Raises: InvalidEAError: If the effective address is invalid.

#### set_name

```
set_name(
    ea: ea_t,
    name: str,
    flags: Union[int, SetNameFlags] = NOCHECK,
) -> bool

```

Set or delete name of an item at the specified address.

Args: ea: Linear address. name: New name. Empty string to delete name. flags: Set name flags (SetNameFlags enum or raw int).

Returns: True if successful, False otherwise.

Raises: InvalidEAError: If the effective address is invalid.

### SetNameFlags

Bases: `IntFlag`

Flags for set_name() function.

Attributes:

- **`AUTO`** –
- **`CHECK`** –
- **`DELTAIL`** –
- **`FORCE`** –
- **`IDBENC`** –
- **`LOCAL`** –
- **`NOCHECK`** –
- **`NODUMMY`** –
- **`NOLIST`** –
- **`NON_AUTO`** –
- **`NON_PUBLIC`** –
- **`NON_WEAK`** –
- **`NOWARN`** –
- **`PUBLIC`** –
- **`WEAK`** –

#### AUTO

```
AUTO = SN_AUTO

```

#### CHECK

```
CHECK = SN_CHECK

```

#### DELTAIL

```
DELTAIL = SN_DELTAIL

```

#### FORCE

```
FORCE = SN_FORCE

```

#### IDBENC

```
IDBENC = SN_IDBENC

```

#### LOCAL

```
LOCAL = SN_LOCAL

```

#### NOCHECK

```
NOCHECK = SN_NOCHECK

```

#### NODUMMY

```
NODUMMY = SN_NODUMMY

```

#### NOLIST

```
NOLIST = SN_NOLIST

```

#### NON_AUTO

```
NON_AUTO = SN_NON_AUTO

```

#### NON_PUBLIC

```
NON_PUBLIC = SN_NON_PUBLIC

```

#### NON_WEAK

```
NON_WEAK = SN_NON_WEAK

```

#### NOWARN

```
NOWARN = SN_NOWARN

```

#### PUBLIC

```
PUBLIC = SN_PUBLIC

```

#### WEAK

```
WEAK = SN_WEAK

```

# `Operands`

## operands

Classes:

- **`AccessType`** – Enumeration of operand access types.
- **`ImmediateOperand`** – Operand representing immediate values (o_imm, o_far, o_near).
- **`MemoryOperand`** – Operand representing memory access (o_mem, o_phrase, o_displ).
- **`Operand`** – Abstract base class for all operand types.
- **`OperandDataType`** – Enumeration of operand data types.
- **`OperandFactory`** – Factory for creating appropriate operand instances.
- **`OperandInfo`** – Basic information about an operand.
- **`OperandType`** – Enumeration of operand types for easier identification.
- **`ProcessorSpecificOperand`** – Operand representing processor-specific types (o_idpspec0-5).
- **`RegisterOperand`** – Operand representing a processor register (o_reg).

### AccessType

Bases: `Enum`

Enumeration of operand access types.

Attributes:

- **`NONE`** –
- **`READ`** –
- **`READ_WRITE`** –
- **`WRITE`** –

#### NONE

```
NONE = 'none'

```

#### READ

```
READ = 'read'

```

#### READ_WRITE

```
READ_WRITE = 'read_write'

```

#### WRITE

```
WRITE = 'write'

```

### ImmediateOperand

```
ImmediateOperand(
    database: Database, operand: op_t, instruction_ea: ea_t
)

```

Bases: `Operand`

Operand representing immediate values (o_imm, o_far, o_near).

Methods:

- **`get_access_type`** – Get a string description of how this operand is accessed.
- **`get_info`** – Get structured information about the operand.
- **`get_name`** – Get the symbolic name for address operands.
- **`get_value`** – Get the immediate value or address.
- **`has_outer_displacement`** – Check if this operand has an outer displacement.
- **`is_address`** – Check if this is an address operand (far/near).
- **`is_floating_point`** – Check if this is a floating point operand.
- **`is_read`** – Check if this operand is read (used) by the instruction.
- **`is_write`** – Check if this operand is written (modified) by the instruction.

Attributes:

- **`data_type`** (`OperandDataType`) – Get the operand data type as an enum.
- **`flags`** (`int`) – Get the operand flags.
- **`is_shown`** (`bool`) – Check if the operand should be displayed.
- **`m_database`** –
- **`number`** (`int`) – Get the operand number (0, 1, 2, etc.).
- **`raw_operand`** (`op_t`) – Get the underlying op_t object.
- **`size_bits`** (`int`) – Get the size of the operand in bits.
- **`size_bytes`** (`int`) – Get the size of the operand in bytes.
- **`type`** (`OperandType`) – Get the operand type as an enum.

#### data_type

```
data_type: OperandDataType

```

Get the operand data type as an enum.

#### flags

```
flags: int

```

Get the operand flags.

#### is_shown

```
is_shown: bool

```

Check if the operand should be displayed.

#### m_database

```
m_database = database

```

#### number

```
number: int

```

Get the operand number (0, 1, 2, etc.).

#### raw_operand

```
raw_operand: op_t

```

Get the underlying op_t object.

#### size_bits

```
size_bits: int

```

Get the size of the operand in bits.

#### size_bytes

```
size_bytes: int

```

Get the size of the operand in bytes.

#### type

```
type: OperandType

```

Get the operand type as an enum.

#### get_access_type

```
get_access_type() -> AccessType

```

Get a string description of how this operand is accessed.

#### get_info

```
get_info() -> OperandInfo

```

Get structured information about the operand.

#### get_name

```
get_name() -> Optional[str]

```

Get the symbolic name for address operands.

#### get_value

```
get_value() -> int

```

Get the immediate value or address.

#### has_outer_displacement

```
has_outer_displacement() -> bool

```

Check if this operand has an outer displacement.

Returns True if the OF_OUTER_DISP flag is set.

#### is_address

```
is_address() -> bool

```

Check if this is an address operand (far/near).

#### is_floating_point

```
is_floating_point() -> bool

```

Check if this is a floating point operand.

#### is_read

```
is_read() -> bool

```

Check if this operand is read (used) by the instruction.

#### is_write

```
is_write() -> bool

```

Check if this operand is written (modified) by the instruction.

### MemoryOperand

```
MemoryOperand(
    database: Database, operand: op_t, instruction_ea: ea_t
)

```

Bases: `Operand`

Operand representing memory access (o_mem, o_phrase, o_displ).

Methods:

- **`get_access_type`** – Get a string description of how this operand is accessed.
- **`get_address`** – Get the address for direct memory operands.
- **`get_displacement`** – Get the base displacement value.
- **`get_formatted_string`** – Get the formatted operand string from IDA.
- **`get_info`** – Get structured information about the operand.
- **`get_name`** – Get the symbolic name for direct memory operands.
- **`get_outer_displacement`** – Get the outer displacement value for complex addressing modes.
- **`get_phrase_number`** – Get the phrase number for register-based operands.
- **`get_value`** – Get the primary value based on memory type.
- **`has_outer_displacement`** – Check if this operand has an outer displacement.
- **`is_direct_memory`** – Check if this is direct memory access.
- **`is_floating_point`** – Check if this is a floating point operand.
- **`is_read`** – Check if this operand is read (used) by the instruction.
- **`is_register_based`** – Check if this uses register-based addressing.
- **`is_write`** – Check if this operand is written (modified) by the instruction.

Attributes:

- **`data_type`** (`OperandDataType`) – Get the operand data type as an enum.
- **`flags`** (`int`) – Get the operand flags.
- **`is_shown`** (`bool`) – Check if the operand should be displayed.
- **`m_database`** –
- **`number`** (`int`) – Get the operand number (0, 1, 2, etc.).
- **`raw_operand`** (`op_t`) – Get the underlying op_t object.
- **`size_bits`** (`int`) – Get the size of the operand in bits.
- **`size_bytes`** (`int`) – Get the size of the operand in bytes.
- **`type`** (`OperandType`) – Get the operand type as an enum.

#### data_type

```
data_type: OperandDataType

```

Get the operand data type as an enum.

#### flags

```
flags: int

```

Get the operand flags.

#### is_shown

```
is_shown: bool

```

Check if the operand should be displayed.

#### m_database

```
m_database = database

```

#### number

```
number: int

```

Get the operand number (0, 1, 2, etc.).

#### raw_operand

```
raw_operand: op_t

```

Get the underlying op_t object.

#### size_bits

```
size_bits: int

```

Get the size of the operand in bits.

#### size_bytes

```
size_bytes: int

```

Get the size of the operand in bytes.

#### type

```
type: OperandType

```

Get the operand type as an enum.

#### get_access_type

```
get_access_type() -> AccessType

```

Get a string description of how this operand is accessed.

#### get_address

```
get_address() -> Optional[ea_t]

```

Get the address for direct memory operands.

#### get_displacement

```
get_displacement() -> Optional[int]

```

Get the base displacement value.

This is the primary displacement used in addressing modes like [reg + disp]. Stored in op_t.addr field.

#### get_formatted_string

```
get_formatted_string() -> Optional[str]

```

Get the formatted operand string from IDA.

#### get_info

```
get_info() -> OperandInfo

```

Get structured information about the operand.

#### get_name

```
get_name() -> Optional[str]

```

Get the symbolic name for direct memory operands.

#### get_outer_displacement

```
get_outer_displacement() -> Optional[int]

```

Get the outer displacement value for complex addressing modes.

Only present when OF_OUTER_DISP flag is set. Stored in op_t.value field.

#### get_phrase_number

```
get_phrase_number() -> Optional[int]

```

Get the phrase number for register-based operands.

#### get_value

```
get_value() -> Any

```

Get the primary value based on memory type.

#### has_outer_displacement

```
has_outer_displacement() -> bool

```

Check if this operand has an outer displacement.

Returns True if the OF_OUTER_DISP flag is set.

#### is_direct_memory

```
is_direct_memory() -> bool

```

Check if this is direct memory access.

#### is_floating_point

```
is_floating_point() -> bool

```

Check if this is a floating point operand.

#### is_read

```
is_read() -> bool

```

Check if this operand is read (used) by the instruction.

#### is_register_based

```
is_register_based() -> bool

```

Check if this uses register-based addressing.

#### is_write

```
is_write() -> bool

```

Check if this operand is written (modified) by the instruction.

### Operand

```
Operand(
    database: Database, operand: op_t, instruction_ea: ea_t
)

```

Bases: `ABC`

Abstract base class for all operand types.

Methods:

- **`get_access_type`** – Get a string description of how this operand is accessed.
- **`get_info`** – Get structured information about the operand.
- **`get_value`** – Get the primary value of the operand.
- **`is_floating_point`** – Check if this is a floating point operand.
- **`is_read`** – Check if this operand is read (used) by the instruction.
- **`is_write`** – Check if this operand is written (modified) by the instruction.

Attributes:

- **`data_type`** (`OperandDataType`) – Get the operand data type as an enum.
- **`flags`** (`int`) – Get the operand flags.
- **`is_shown`** (`bool`) – Check if the operand should be displayed.
- **`m_database`** –
- **`number`** (`int`) – Get the operand number (0, 1, 2, etc.).
- **`raw_operand`** (`op_t`) – Get the underlying op_t object.
- **`size_bits`** (`int`) – Get the size of the operand in bits.
- **`size_bytes`** (`int`) – Get the size of the operand in bytes.
- **`type`** (`OperandType`) – Get the operand type as an enum.

#### data_type

```
data_type: OperandDataType

```

Get the operand data type as an enum.

#### flags

```
flags: int

```

Get the operand flags.

#### is_shown

```
is_shown: bool

```

Check if the operand should be displayed.

#### m_database

```
m_database = database

```

#### number

```
number: int

```

Get the operand number (0, 1, 2, etc.).

#### raw_operand

```
raw_operand: op_t

```

Get the underlying op_t object.

#### size_bits

```
size_bits: int

```

Get the size of the operand in bits.

#### size_bytes

```
size_bytes: int

```

Get the size of the operand in bytes.

#### type

```
type: OperandType

```

Get the operand type as an enum.

#### get_access_type

```
get_access_type() -> AccessType

```

Get a string description of how this operand is accessed.

#### get_info

```
get_info() -> OperandInfo

```

Get structured information about the operand.

#### get_value

```
get_value() -> Any

```

Get the primary value of the operand.

#### is_floating_point

```
is_floating_point() -> bool

```

Check if this is a floating point operand.

#### is_read

```
is_read() -> bool

```

Check if this operand is read (used) by the instruction.

#### is_write

```
is_write() -> bool

```

Check if this operand is written (modified) by the instruction.

### OperandDataType

Bases: `IntEnum`

Enumeration of operand data types.

Attributes:

- **`BITFIELD`** –
- **`BYTE`** –
- **`BYTE16`** –
- **`BYTE32`** –
- **`BYTE64`** –
- **`CODE`** –
- **`DOUBLE`** –
- **`DWORD`** –
- **`FLOAT`** –
- **`FWORD`** –
- **`HALF`** –
- **`LDBL`** –
- **`PACKREAL`** –
- **`QWORD`** –
- **`STRING`** –
- **`TBYTE`** –
- **`UNICODE`** –
- **`VOID`** –
- **`WORD`** –

#### BITFIELD

```
BITFIELD = dt_bitfild

```

#### BYTE

```
BYTE = dt_byte

```

#### BYTE16

```
BYTE16 = dt_byte16

```

#### BYTE32

```
BYTE32 = dt_byte32

```

#### BYTE64

```
BYTE64 = dt_byte64

```

#### CODE

```
CODE = dt_code

```

#### DOUBLE

```
DOUBLE = dt_double

```

#### DWORD

```
DWORD = dt_dword

```

#### FLOAT

```
FLOAT = dt_float

```

#### FWORD

```
FWORD = dt_fword

```

#### HALF

```
HALF = dt_half

```

#### LDBL

```
LDBL = dt_ldbl

```

#### PACKREAL

```
PACKREAL = dt_packreal

```

#### QWORD

```
QWORD = dt_qword

```

#### STRING

```
STRING = dt_string

```

#### TBYTE

```
TBYTE = dt_tbyte

```

#### UNICODE

```
UNICODE = dt_unicode

```

#### VOID

```
VOID = dt_void

```

#### WORD

```
WORD = dt_word

```

### OperandFactory

Factory for creating appropriate operand instances.

Methods:

- **`create`** – Create an operand instance based on the operand type.

#### create

```
create(
    database: Database, operand: op_t, instruction_ea: int
) -> Optional[Operand]

```

Create an operand instance based on the operand type.

### OperandInfo

```
OperandInfo(
    number: int,
    type: OperandType,
    data_type: OperandDataType,
    access_type: AccessType,
    size_bytes: int,
    size_bits: int,
    flags: int,
    is_hidden: bool,
    is_floating_point: bool,
)

```

Basic information about an operand.

Attributes:

- **`access_type`** (`AccessType`) –
- **`data_type`** (`OperandDataType`) –
- **`flags`** (`int`) –
- **`is_floating_point`** (`bool`) –
- **`is_hidden`** (`bool`) –
- **`number`** (`int`) –
- **`size_bits`** (`int`) –
- **`size_bytes`** (`int`) –
- **`type`** (`OperandType`) –

#### access_type

```
access_type: AccessType

```

#### data_type

```
data_type: OperandDataType

```

#### flags

```
flags: int

```

#### is_floating_point

```
is_floating_point: bool

```

#### is_hidden

```
is_hidden: bool

```

#### number

```
number: int

```

#### size_bits

```
size_bits: int

```

#### size_bytes

```
size_bytes: int

```

#### type

```
type: OperandType

```

### OperandType

Bases: `IntEnum`

Enumeration of operand types for easier identification.

Attributes:

- **`DISPLACEMENT`** –
- **`FAR_ADDRESS`** –
- **`IMMEDIATE`** –
- **`MEMORY`** –
- **`NEAR_ADDRESS`** –
- **`PHRASE`** –
- **`PROCESSOR_SPECIFIC_0`** –
- **`PROCESSOR_SPECIFIC_1`** –
- **`PROCESSOR_SPECIFIC_2`** –
- **`PROCESSOR_SPECIFIC_3`** –
- **`PROCESSOR_SPECIFIC_4`** –
- **`PROCESSOR_SPECIFIC_5`** –
- **`REGISTER`** –
- **`VOID`** –

#### DISPLACEMENT

```
DISPLACEMENT = o_displ

```

#### FAR_ADDRESS

```
FAR_ADDRESS = o_far

```

#### IMMEDIATE

```
IMMEDIATE = o_imm

```

#### MEMORY

```
MEMORY = o_mem

```

#### NEAR_ADDRESS

```
NEAR_ADDRESS = o_near

```

#### PHRASE

```
PHRASE = o_phrase

```

#### PROCESSOR_SPECIFIC_0

```
PROCESSOR_SPECIFIC_0 = o_idpspec0

```

#### PROCESSOR_SPECIFIC_1

```
PROCESSOR_SPECIFIC_1 = o_idpspec1

```

#### PROCESSOR_SPECIFIC_2

```
PROCESSOR_SPECIFIC_2 = o_idpspec2

```

#### PROCESSOR_SPECIFIC_3

```
PROCESSOR_SPECIFIC_3 = o_idpspec3

```

#### PROCESSOR_SPECIFIC_4

```
PROCESSOR_SPECIFIC_4 = o_idpspec4

```

#### PROCESSOR_SPECIFIC_5

```
PROCESSOR_SPECIFIC_5 = o_idpspec5

```

#### REGISTER

```
REGISTER = o_reg

```

#### VOID

```
VOID = o_void

```

### ProcessorSpecificOperand

```
ProcessorSpecificOperand(
    database: Database, operand: op_t, instruction_ea: int
)

```

Bases: `Operand`

Operand representing processor-specific types (o_idpspec0-5).

Methods:

- **`get_access_type`** – Get a string description of how this operand is accessed.
- **`get_info`** – Get structured information about the operand.
- **`get_spec_type`** – Get the processor-specific type number (0-5).
- **`get_value`** – Return raw value for processor-specific operands.
- **`is_floating_point`** – Check if this is a floating point operand.
- **`is_read`** – Check if this operand is read (used) by the instruction.
- **`is_write`** – Check if this operand is written (modified) by the instruction.

Attributes:

- **`data_type`** (`OperandDataType`) – Get the operand data type as an enum.
- **`flags`** (`int`) – Get the operand flags.
- **`is_shown`** (`bool`) – Check if the operand should be displayed.
- **`m_database`** –
- **`number`** (`int`) – Get the operand number (0, 1, 2, etc.).
- **`raw_operand`** (`op_t`) – Get the underlying op_t object.
- **`size_bits`** (`int`) – Get the size of the operand in bits.
- **`size_bytes`** (`int`) – Get the size of the operand in bytes.
- **`type`** (`OperandType`) – Get the operand type as an enum.

#### data_type

```
data_type: OperandDataType

```

Get the operand data type as an enum.

#### flags

```
flags: int

```

Get the operand flags.

#### is_shown

```
is_shown: bool

```

Check if the operand should be displayed.

#### m_database

```
m_database = database

```

#### number

```
number: int

```

Get the operand number (0, 1, 2, etc.).

#### raw_operand

```
raw_operand: op_t

```

Get the underlying op_t object.

#### size_bits

```
size_bits: int

```

Get the size of the operand in bits.

#### size_bytes

```
size_bytes: int

```

Get the size of the operand in bytes.

#### type

```
type: OperandType

```

Get the operand type as an enum.

#### get_access_type

```
get_access_type() -> AccessType

```

Get a string description of how this operand is accessed.

#### get_info

```
get_info() -> OperandInfo

```

Get structured information about the operand.

#### get_spec_type

```
get_spec_type() -> int

```

Get the processor-specific type number (0-5).

#### get_value

```
get_value() -> Any

```

Return raw value for processor-specific operands.

#### is_floating_point

```
is_floating_point() -> bool

```

Check if this is a floating point operand.

#### is_read

```
is_read() -> bool

```

Check if this operand is read (used) by the instruction.

#### is_write

```
is_write() -> bool

```

Check if this operand is written (modified) by the instruction.

### RegisterOperand

```
RegisterOperand(
    database: Database, operand: op_t, instruction_ea: ea_t
)

```

Bases: `Operand`

Operand representing a processor register (o_reg).

Methods:

- **`get_access_type`** – Get a string description of how this operand is accessed.
- **`get_info`** – Get structured information about the operand.
- **`get_register_name`** – Get the name of this register using the operand's size.
- **`get_value`** –
- **`is_floating_point`** – Check if this is a floating point operand.
- **`is_read`** – Check if this operand is read (used) by the instruction.
- **`is_write`** – Check if this operand is written (modified) by the instruction.

Attributes:

- **`data_type`** (`OperandDataType`) – Get the operand data type as an enum.
- **`flags`** (`int`) – Get the operand flags.
- **`is_shown`** (`bool`) – Check if the operand should be displayed.
- **`m_database`** –
- **`number`** (`int`) – Get the operand number (0, 1, 2, etc.).
- **`raw_operand`** (`op_t`) – Get the underlying op_t object.
- **`register_number`** (`int`) – Get the register number.
- **`size_bits`** (`int`) – Get the size of the operand in bits.
- **`size_bytes`** (`int`) – Get the size of the operand in bytes.
- **`type`** (`OperandType`) – Get the operand type as an enum.

#### data_type

```
data_type: OperandDataType

```

Get the operand data type as an enum.

#### flags

```
flags: int

```

Get the operand flags.

#### is_shown

```
is_shown: bool

```

Check if the operand should be displayed.

#### m_database

```
m_database = database

```

#### number

```
number: int

```

Get the operand number (0, 1, 2, etc.).

#### raw_operand

```
raw_operand: op_t

```

Get the underlying op_t object.

#### register_number

```
register_number: int

```

Get the register number.

#### size_bits

```
size_bits: int

```

Get the size of the operand in bits.

#### size_bytes

```
size_bytes: int

```

Get the size of the operand in bytes.

#### type

```
type: OperandType

```

Get the operand type as an enum.

#### get_access_type

```
get_access_type() -> AccessType

```

Get a string description of how this operand is accessed.

#### get_info

```
get_info() -> OperandInfo

```

Get structured information about the operand.

#### get_register_name

```
get_register_name() -> str

```

Get the name of this register using the operand's size.

#### get_value

```
get_value() -> int

```

#### is_floating_point

```
is_floating_point() -> bool

```

Check if this is a floating point operand.

#### is_read

```
is_read() -> bool

```

Check if this operand is read (used) by the instruction.

#### is_write

```
is_write() -> bool

```

Check if this operand is written (modified) by the instruction.

# `Segments`

## segments

Classes:

- **`AddSegmentFlags`** –
- **`AddressingMode`** –
- **`PredefinedClass`** –
- **`SegmentPermissions`** –
- **`Segments`** – Provides access to segment-related operations in the IDA database.

### AddSegmentFlags

Bases: `IntFlag`

Attributes:

- **`FILLGAP`** –
- **`IDBENC`** –
- **`NOAA`** –
- **`NONE`** –
- **`NOSREG`** –
- **`NOTRUNC`** –
- **`OR_DIE`** –
- **`QUIET`** –
- **`SPARSE`** –

#### FILLGAP

```
FILLGAP = ADDSEG_FILLGAP

```

#### IDBENC

```
IDBENC = ADDSEG_IDBENC

```

#### NOAA

```
NOAA = ADDSEG_NOAA

```

#### NONE

```
NONE = 0

```

#### NOSREG

```
NOSREG = ADDSEG_NOSREG

```

#### NOTRUNC

```
NOTRUNC = ADDSEG_NOTRUNC

```

#### OR_DIE

```
OR_DIE = ADDSEG_OR_DIE

```

#### QUIET

```
QUIET = ADDSEG_QUIET

```

#### SPARSE

```
SPARSE = ADDSEG_SPARSE

```

### AddressingMode

Bases: `IntEnum`

Attributes:

- **`BIT16`** –
- **`BIT32`** –
- **`BIT64`** –

#### BIT16

```
BIT16 = 0

```

#### BIT32

```
BIT32 = 1

```

#### BIT64

```
BIT64 = 2

```

### PredefinedClass

Bases: `Enum`

Attributes:

- **`ABS`** –
- **`BSS`** –
- **`CODE`** –
- **`COMM`** –
- **`CONST`** –
- **`DATA`** –
- **`STACK`** –
- **`XTRN`** –

#### ABS

```
ABS = 'ABS'

```

#### BSS

```
BSS = 'BSS'

```

#### CODE

```
CODE = 'CODE'

```

#### COMM

```
COMM = 'COMM'

```

#### CONST

```
CONST = 'CONST'

```

#### DATA

```
DATA = 'DATA'

```

#### STACK

```
STACK = 'STACK'

```

#### XTRN

```
XTRN = 'XTRN'

```

### SegmentPermissions

Bases: `IntFlag`

Attributes:

- **`ALL`** –
- **`EXEC`** –
- **`NONE`** –
- **`READ`** –
- **`WRITE`** –

#### ALL

```
ALL = SEGPERM_MAXVAL

```

#### EXEC

```
EXEC = SEGPERM_EXEC

```

#### NONE

```
NONE = 0

```

#### READ

```
READ = SEGPERM_READ

```

#### WRITE

```
WRITE = SEGPERM_WRITE

```

### Segments

```
Segments(database: Database)

```

Bases: `DatabaseEntity`

Provides access to segment-related operations in the IDA database.

Can be used to iterate over all segments in the opened database.

Args: database: Reference to the active IDA database.

Note: Since this class does not manage the lifetime of IDA kernel objects (segment_t\*), it is recommended to use these pointers within a limited scope. Obtain the pointer, perform the necessary operations, and avoid retaining references beyond the immediate context to prevent potential issues with object invalidation.

Methods:

- **`add`** – Adds a new segment to the IDA database.
- **`add_permissions`** – OR the given permission bits into the existing segment permissions.
- **`append`** – Append a new segment directly after the last segment in the database.
- **`get_all`** – Retrieves an iterator over all segments in the database.
- **`get_at`** – Retrieves the segment that contains the given address.
- **`get_bitness`** – Get segment bitness (16/32/64).
- **`get_by_name`** – Find segment by name.
- **`get_class`** – Get segment class name.
- **`get_comment`** – Get comment for segment.
- **`get_name`** – Retrieves the name of the given segment.
- **`get_size`** – Calculate segment size in bytes.
- **`remove_permissions`** – Clear the given permission bits from the existing segment permissions.
- **`set_addressing_mode`** – Sets the segment addressing mode (16-bit, 32-bit, or 64-bit).
- **`set_comment`** – Set comment for segment.
- **`set_name`** – Renames a segment.
- **`set_permissions`** – Set the segment permissions exactly to perms (overwrites existing flags).

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### add

```
add(
    seg_para: ea_t,
    start_ea: ea_t,
    end_ea: ea_t,
    seg_name: Optional[str] = None,
    seg_class: Optional[Union[str, PredefinedClass]] = None,
    flags: AddSegmentFlags = NONE,
) -> Optional[segment_t]

```

Adds a new segment to the IDA database.

Args: seg_para: Segment base paragraph. start_ea: Start address of the segment (linear EA). end_ea: End address of the segment (exclusive). seg_name: Name of new segment (optional). seg_class: Class of the segment (optional). Accepts str or PredefinedClass. flags: Add segment flags (AddSegmentFlags).

Returns: The created segment_t on success, or None on failure.

#### add_permissions

```
add_permissions(
    segment: segment_t, perms: SegmentPermissions
) -> bool

```

OR the given permission bits into the existing segment permissions.

#### append

```
append(
    seg_para: ea_t,
    seg_size: ea_t,
    seg_name: Optional[str] = None,
    seg_class: Optional[Union[str, PredefinedClass]] = None,
    flags: AddSegmentFlags = NONE,
) -> Optional[segment_t]

```

Append a new segment directly after the last segment in the database.

Args: seg_para: Segment base paragraph (selector/paragraph as used by IDA). seg_size: Desired size in bytes for the new segment (must be > 0). seg_name: Optional name for the new segment. seg_class: Optional class for the new segment (str or PredefinedClass). flags: Add segment flags (AddSegmentFlags).

Returns: The created segment_t on success, or None on failure.

Raises: ValueError: If seg_size is \<= 0. RuntimeError: If there are no existing segments to append after.

#### get_all

```
get_all() -> Iterator[segment_t]

```

Retrieves an iterator over all segments in the database.

Returns: A generator yielding all segment_t objects in the database.

#### get_at

```
get_at(ea: ea_t) -> Optional[segment_t]

```

Retrieves the segment that contains the given address.

Args: ea: The effective address to search.

Returns: A segment_t object, or None if none found.

Raises: InvalidEAError: If the effective address is invalid.

#### get_bitness

```
get_bitness(segment: segment_t) -> int

```

Get segment bitness (16/32/64).

#### get_by_name

```
get_by_name(name: str) -> Optional[segment_t]

```

Find segment by name.

Args: name: Segment name to search for

Returns: segment_t if found, None otherwise

#### get_class

```
get_class(segment: segment_t) -> Optional[str]

```

Get segment class name.

#### get_comment

```
get_comment(
    segment: segment_t, repeatable: bool = False
) -> str

```

Get comment for segment.

Args: segment: The segment to get comment from. repeatable: If True, retrieves repeatable comment (shows at all identical operands). If False, retrieves non-repeatable comment (shows only at this segment).

Returns: Comment text, or empty string if no comment exists.

#### get_name

```
get_name(segment: segment_t) -> str

```

Retrieves the name of the given segment.

Args: segment: The segment to get the name from.

Returns: The segment name as a string, or an empty string if unavailable.

#### get_size

```
get_size(segment: segment_t) -> int

```

Calculate segment size in bytes.

#### remove_permissions

```
remove_permissions(
    segment: segment_t, perms: SegmentPermissions
) -> bool

```

Clear the given permission bits from the existing segment permissions.

#### set_addressing_mode

```
set_addressing_mode(
    segment: segment_t, mode: AddressingMode
) -> bool

```

Sets the segment addressing mode (16-bit, 32-bit, or 64-bit).

Args: segment: The target segment object. mode: AddressingMode enum value.

Returns: True if successful, False otherwise.

#### set_comment

```
set_comment(
    segment: segment_t,
    comment: str,
    repeatable: bool = False,
) -> bool

```

Set comment for segment.

Args: segment: The segment to set comment for. comment: Comment text to set. repeatable: If True, creates a repeatable comment (shows at all identical operands). If False, creates a non-repeatable comment (shows only at this segment).

Returns: True if successful, False otherwise.

#### set_name

```
set_name(segment: segment_t, name: str) -> bool

```

Renames a segment.

Args: segment: The segment to rename. name: The new name to assign to the segment.

Returns: True if the rename operation succeeded, False otherwise.

#### set_permissions

```
set_permissions(
    segment: segment_t, perms: SegmentPermissions
) -> bool

```

Set the segment permissions exactly to `perms` (overwrites existing flags).

# `Signature Files`

## signature_files

Classes:

- **`FileInfo`** – Represents information about a FLIRT signature file application.
- **`MatchInfo`** – Represents information about a single function matched by a FLIRT signature.
- **`SignatureFiles`** – Provides access to FLIRT signature (.sig) files in the IDA database.

### FileInfo

```
FileInfo(
    path: str = '',
    matches: int = 0,
    functions: List[MatchInfo] = list(),
)

```

Represents information about a FLIRT signature file application. Contains the signature file path, number of matches, and details of matched functions.

Attributes:

- **`functions`** (`List[MatchInfo]`) –
- **`matches`** (`int`) –
- **`path`** (`str`) –

#### functions

```
functions: List[MatchInfo] = field(default_factory=list)

```

#### matches

```
matches: int = 0

```

#### path

```
path: str = ''

```

### MatchInfo

```
MatchInfo(addr: ea_t, name: str = '', lib: str = '')

```

Represents information about a single function matched by a FLIRT signature.

Attributes:

- **`addr`** (`ea_t`) –
- **`lib`** (`str`) –
- **`name`** (`str`) –

#### addr

```
addr: ea_t

```

#### lib

```
lib: str = ''

```

#### name

```
name: str = ''

```

### SignatureFiles

```
SignatureFiles(database: Database)

```

Bases: `DatabaseEntity`

Provides access to FLIRT signature (.sig) files in the IDA database.

Args: database: Reference to the active IDA database.

Methods:

- **`apply`** – Applies signature files to current database.
- **`create`** – Create signature files (.pat and .sig) from current database.
- **`get_files`** – Retrieves a list of available FLIRT signature (.sig) files.
- **`get_index`** – Get index of applied signature file.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### apply

```
apply(
    path: Path, probe_only: bool = False
) -> List[FileInfo]

```

Applies signature files to current database.

Args: path: Path to the signature file or directory with sig files. probe_only: If true, signature files are only probed (apply operation is undone).

Returns: A list of FileInfo objects containing application details.

#### create

```
create(pat_only: bool = False) -> List[str] | None

```

Create signature files (.pat and .sig) from current database.

Args: pat_only: If true, generate only PAT file.

Returns: A list containing paths to the generated files. In case of failure, returns None.

#### get_files

```
get_files(
    directories: Optional[List[Path]] = None,
) -> List[Path]

```

Retrieves a list of available FLIRT signature (.sig) files.

Args: directories: Optional list of paths to directories containing FLIRT signature files. If the parameter is missing, IDA signature folders will be used.

Returns: A list of available signature file paths.

#### get_index

```
get_index(path: Path) -> int

```

Get index of applied signature file.

Args: path: Path to the signature file.

Returns: Index of applied signature file, -1 if not found.

# `Strings`

## strings

Classes:

- **`StringItem`** – Represents detailed information about a string in the IDA database.
- **`StringListConfig`** – Configuration for building the internal string list.
- **`StringType`** – String type constants.
- **`Strings`** – Provides access to string-related operations in the IDA database.

### StringItem

```
StringItem(address: ea_t, length: int, internal_type: int)

```

Represents detailed information about a string in the IDA database.

Attributes:

- **`address`** (`ea_t`) – String address
- **`contents`** (`bytes`) – Returns utf-8 encoded string contents.
- **`encoding`** (`str`) – Returns internal IDA string encoding, e.g. 'iso-8859-1'.
- **`internal_type`** (`int`) – Internal IDA string type, including internal string encoding
- **`length`** (`int`) – String length in number of characters
- **`type`** (`StringType`) – Return string type enum value, e.g. 'C-style null-terminated string'.

#### address

```
address: ea_t

```

String address

#### contents

```
contents: bytes

```

Returns utf-8 encoded string contents.

#### encoding

```
encoding: str

```

Returns internal IDA string encoding, e.g. 'iso-8859-1'. Note that retrieved string contents will always be utf-8 encoded.

#### internal_type

```
internal_type: int

```

Internal IDA string type, including internal string encoding

#### length

```
length: int

```

String length in number of characters

#### type

```
type: StringType

```

Return string type enum value, e.g. 'C-style null-terminated string'.

### StringListConfig

```
StringListConfig(
    string_types: list[StringType] = lambda: [C](),
    min_len: int = 5,
    only_ascii_7bit: bool = True,
    only_existing: bool = False,
    ignore_instructions: bool = False,
)

```

Configuration for building the internal string list.

Attributes:

- **`ignore_instructions`** (`bool`) –
- **`min_len`** (`int`) –
- **`only_ascii_7bit`** (`bool`) –
- **`only_existing`** (`bool`) –
- **`string_types`** (`list[StringType]`) –

#### ignore_instructions

```
ignore_instructions: bool = False

```

#### min_len

```
min_len: int = 5

```

#### only_ascii_7bit

```
only_ascii_7bit: bool = True

```

#### only_existing

```
only_existing: bool = False

```

#### string_types

```
string_types: list[StringType] = field(
    default_factory=lambda: [C]
)

```

### StringType

Bases: `IntEnum`

String type constants.

Attributes:

- **`C`** –
- **`C_16`** –
- **`C_32`** –
- **`LEN2`** –
- **`LEN2_16`** –
- **`LEN2_32`** –
- **`LEN4`** –
- **`LEN4_16`** –
- **`LEN4_32`** –
- **`PASCAL`** –
- **`PASCAL_16`** –
- **`PASCAL_32`** –

#### C

```
C = STRTYPE_C

```

#### C_16

```
C_16 = STRTYPE_C_16

```

#### C_32

```
C_32 = STRTYPE_C_32

```

#### LEN2

```
LEN2 = STRTYPE_LEN2

```

#### LEN2_16

```
LEN2_16 = STRTYPE_LEN2_16

```

#### LEN2_32

```
LEN2_32 = STRTYPE_LEN2_32

```

#### LEN4

```
LEN4 = STRTYPE_LEN4

```

#### LEN4_16

```
LEN4_16 = STRTYPE_LEN4_16

```

#### LEN4_32

```
LEN4_32 = STRTYPE_LEN4_32

```

#### PASCAL

```
PASCAL = STRTYPE_PASCAL

```

#### PASCAL_16

```
PASCAL_16 = STRTYPE_PASCAL_16

```

#### PASCAL_32

```
PASCAL_32 = STRTYPE_PASCAL_32

```

### Strings

```
Strings(database: Database)

```

Bases: `DatabaseEntity`

Provides access to string-related operations in the IDA database.

Can be used to iterate over all strings in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`clear`** – Clear the string list, strings will not be saved in the database.
- **`get_all`** – Retrieves an iterator over all extracted strings in the database.
- **`get_at`** – Retrieves detailed string information at the specified address.
- **`get_at_index`** – Retrieves the string at the specified index.
- **`get_between`** – Retrieves strings within the specified address range.
- **`rebuild`** – Rebuild the string list from scratch.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### clear

```
clear() -> None

```

Clear the string list, strings will not be saved in the database.

#### get_all

```
get_all() -> Iterator[StringItem]

```

Retrieves an iterator over all extracted strings in the database.

Returns: An iterator over all strings.

#### get_at

```
get_at(ea: ea_t) -> Optional[StringItem]

```

Retrieves detailed string information at the specified address.

Args: ea: The effective address.

Returns: A StringItem object if found, None otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### get_at_index

```
get_at_index(index: int) -> StringItem

```

Retrieves the string at the specified index.

Args: index: Index of the string to retrieve.

Returns: A StringItem object at the given index. In case of error, returns None.

#### get_between

```
get_between(
    start_ea: ea_t, end_ea: ea_t
) -> Iterator[StringItem]

```

Retrieves strings within the specified address range.

Args: start_ea: Start address of the range (inclusive). end_ea: End address of the range (exclusive).

Returns: An iterator over strings in the range.

Raises: InvalidEAError: If start_ea or end_ea are not within database bounds. InvalidParameterError: If start_ea >= end_ea.

#### rebuild

```
rebuild(
    config: StringListConfig = StringListConfig(),
) -> None

```

Rebuild the string list from scratch. This should be called to get an up-to-date string list.

# `Types`

## types

Classes:

- **`ArrayDetails`** –
- **`BitfieldAttr`** – Bitfield Type flags
- **`BitfieldDetails`** – Bitfield type details
- **`EnumAttr`** – Enum Type flags
- **`EnumDetails`** – Enum type details.
- **`FuncAttr`** – Function Type flags
- **`FuncDetails`** – Function type details.
- **`LibraryAddFlags`** – Flags for changing the way type libraries are added to the database
- **`LibraryAddResult`** – Return values for library add operation
- **`NotSupportedWarning`** – Warning for unsupported features in the underlying idapython API
- **`PtrAttr`** – Pointer Type Flags
- **`PtrDetails`** –
- **`TypeApplyFlags`** – Flags that control how type information is applied to a given address
- **`TypeAttr`** – General Type attributes
- **`TypeDetails`** – Comprehensive type information with category-specific attributes
- **`TypeDetailsVisitor`** – Visitor class for types.
- **`TypeFormattingFlags`** – Type formatting flags used to control type parsing, formatting and printing
- **`TypeKind`** – Type category enumeration.
- **`TypeManipulationFlags`** – Flags to be used
- **`Types`** – Provides access to type information and manipulation in the IDA database.
- **`UdtAttr`** – User Defined Type flags
- **`UdtDetails`** – User Defined Type details

### ArrayDetails

```
ArrayDetails()

```

Methods:

- **`from_tinfo_t`** – Extract array type attributes and details.

Attributes:

- **`base`** (`int`) – Get array base.
- **`element_type`** (`tinfo_t`) – Get array element type.
- **`length`** (`int`) – Get number of elements.

#### base

```
base: int

```

Get array base.

#### element_type

```
element_type: tinfo_t

```

Get array element type.

#### length

```
length: int

```

Get number of elements.

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> Optional[ArrayDetails]

```

Extract array type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Array type details object filled with extracted information.

### BitfieldAttr

Bases: `Flag`

Bitfield Type flags

Attributes:

- **`UNSIGNED`** –
- **`VALID`** –

#### UNSIGNED

```
UNSIGNED = auto()

```

#### VALID

```
VALID = auto()

```

### BitfieldDetails

```
BitfieldDetails()

```

Bitfield type details

Methods:

- **`from_tinfo_t`** – Extract bitfield type attributes and details.

Attributes:

- **`attributes`** (`Optional[BitfieldAttr]`) – Get the bitfield type attributes.

#### attributes

```
attributes: Optional[BitfieldAttr]

```

Get the bitfield type attributes.

#### from_tinfo_t

```
from_tinfo_t(
    type_info: tinfo_t,
) -> Optional[BitfieldDetails]

```

Extract bitfield type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Bitfield type details object filled with extracted information.

### EnumAttr

Bases: `Flag`

Enum Type flags

Attributes:

- **`BINARY`** –
- **`BITMASK`** –
- **`CHAR`** –
- **`DECIMAL`** –
- **`HEXADECIMAL`** –
- **`LEADING_ZEROS`** –
- **`OCTAL`** –
- **`SIGNED`** –
- **`SIGNED_BINARY`** –
- **`SIGNED_HEXADECIMAL`** –
- **`SIGNED_OCTAL`** –
- **`UNSIGNED_DECIMAL`** –

#### BINARY

```
BINARY = auto()

```

#### BITMASK

```
BITMASK = auto()

```

#### CHAR

```
CHAR = auto()

```

#### DECIMAL

```
DECIMAL = auto()

```

#### HEXADECIMAL

```
HEXADECIMAL = auto()

```

#### LEADING_ZEROS

```
LEADING_ZEROS = auto()

```

#### OCTAL

```
OCTAL = auto()

```

#### SIGNED

```
SIGNED = auto()

```

#### SIGNED_BINARY

```
SIGNED_BINARY = auto()

```

#### SIGNED_HEXADECIMAL

```
SIGNED_HEXADECIMAL = auto()

```

#### SIGNED_OCTAL

```
SIGNED_OCTAL = auto()

```

#### UNSIGNED_DECIMAL

```
UNSIGNED_DECIMAL = auto()

```

### EnumDetails

```
EnumDetails()

```

Enum type details.

Methods:

- **`from_tinfo_t`** – Extract enum type attributes and details.

Attributes:

- **`attributes`** (`Optional[EnumAttr]`) – Get enum type attributes

#### attributes

```
attributes: Optional[EnumAttr]

```

Get enum type attributes

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> Optional[EnumDetails]

```

Extract enum type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Enum type details object filled with extracted information.

### FuncAttr

Bases: `Flag`

Function Type flags

Attributes:

- **`CONST`** –
- **`CONSTRUCTOR`** –
- **`DESTRUCTOR`** –
- **`GOLANG_CC`** –
- **`HIGH_LEVEL`** –
- **`NO_RET`** –
- **`PURE`** –
- **`STATIC`** –
- **`SWIFT_CC`** –
- **`USER_CC`** –
- **`VARARG_CC`** –
- **`VIRTUAL`** –

#### CONST

```
CONST = auto()

```

#### CONSTRUCTOR

```
CONSTRUCTOR = auto()

```

#### DESTRUCTOR

```
DESTRUCTOR = auto()

```

#### GOLANG_CC

```
GOLANG_CC = auto()

```

#### HIGH_LEVEL

```
HIGH_LEVEL = auto()

```

#### NO_RET

```
NO_RET = auto()

```

#### PURE

```
PURE = auto()

```

#### STATIC

```
STATIC = auto()

```

#### SWIFT_CC

```
SWIFT_CC = auto()

```

#### USER_CC

```
USER_CC = auto()

```

#### VARARG_CC

```
VARARG_CC = auto()

```

#### VIRTUAL

```
VIRTUAL = auto()

```

### FuncDetails

```
FuncDetails()

```

Function type details.

Methods:

- **`from_tinfo_t`** – Extract function type attributes and details.

Attributes:

- **`attributes`** (`Optional[FuncAttr]`) – Get the function type attributes.

#### attributes

```
attributes: Optional[FuncAttr]

```

Get the function type attributes.

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> Optional[FuncDetails]

```

Extract function type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Function type details object filled with extracted information.

### LibraryAddFlags

Bases: `IntFlag`

Flags for changing the way type libraries are added to the database

Attributes:

- **`ADD_DEFAULT`** – Default behavior
- **`ADD_INCOMPATIBLE`** – Add incompatible type libraries
- **`ADD_SILENT`** – Do not ask any questions

#### ADD_DEFAULT

```
ADD_DEFAULT = ADDTIL_DEFAULT

```

Default behavior

#### ADD_INCOMPATIBLE

```
ADD_INCOMPATIBLE = ADDTIL_INCOMP

```

Add incompatible type libraries

#### ADD_SILENT

```
ADD_SILENT = ADDTIL_SILENT

```

Do not ask any questions

### LibraryAddResult

Bases: `IntEnum`

Return values for library add operation

Attributes:

- **`ABORTED`** – Library not loaded, rejected by the user
- **`FAILED`** – Loading library failed
- **`INCOMPATIBLE`** – Library loaded but is incompatible
- **`SUCCESS`** – Library successfully loaded

#### ABORTED

```
ABORTED = ADDTIL_ABORTED

```

Library not loaded, rejected by the user

#### FAILED

```
FAILED = ADDTIL_FAILED

```

Loading library failed

#### INCOMPATIBLE

```
INCOMPATIBLE = ADDTIL_COMP

```

Library loaded but is incompatible

#### SUCCESS

```
SUCCESS = ADDTIL_OK

```

Library successfully loaded

### NotSupportedWarning

Bases: `Warning`

Warning for unsupported features in the underlying idapython API

### PtrAttr

Bases: `Flag`

Pointer Type Flags

Attributes:

- **`CODE_POINTER`** –
- **`SHIFTED`** –

#### CODE_POINTER

```
CODE_POINTER = auto()

```

#### SHIFTED

```
SHIFTED = auto()

```

### PtrDetails

```
PtrDetails()

```

Methods:

- **`from_tinfo_t`** – Extract pointer type attributes and details.

Attributes:

- **`attributes`** (`Optional[PtrAttr]`) – Get pointer type attributes.

#### attributes

```
attributes: Optional[PtrAttr]

```

Get pointer type attributes.

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> Optional[PtrDetails]

```

Extract pointer type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Pointer type details object filled with extracted information.

### TypeApplyFlags

Bases: `IntFlag`

Flags that control how type information is applied to a given address

Attributes:

- **`DEFINITE`** –
- **`DELAYFUNC`** –
- **`GUESSED`** –
- **`STRICT`** –

#### DEFINITE

```
DEFINITE = TINFO_DEFINITE

```

#### DELAYFUNC

```
DELAYFUNC = TINFO_DELAYFUNC

```

#### GUESSED

```
GUESSED = TINFO_GUESSED

```

#### STRICT

```
STRICT = TINFO_STRICT

```

### TypeAttr

Bases: `Flag`

General Type attributes

Attributes:

- **`ARITHMETIC`** –
- **`ARRAY`** –
- **`ATTACHED`** –
- **`BITFIELD`** –
- **`BOOL`** –
- **`CHAR`** –
- **`COMPLEX`** –
- **`CONST`** –
- **`CORRECT`** –
- **`DECL_ARRAY`** –
- **`DECL_BITFIELD`** –
- **`DECL_BOOL`** –
- **`DECL_CHAR`** –
- **`DECL_COMPLEX`** –
- **`DECL_CONST`** –
- **`DECL_DOUBLE`** –
- **`DECL_ENUM`** –
- **`DECL_FLOAT`** –
- **`DECL_FLOATING`** –
- **`DECL_FUNC`** –
- **`DECL_INT`** –
- **`DECL_INT128`** –
- **`DECL_INT16`** –
- **`DECL_INT32`** –
- **`DECL_INT64`** –
- **`DECL_LAST`** –
- **`DECL_LDOUBLE`** –
- **`DECL_PAF`** –
- **`DECL_PARTIAL`** –
- **`DECL_PTR`** –
- **`DECL_STRUCT`** –
- **`DECL_SUE`** –
- **`DECL_TBYTE`** –
- **`DECL_TYPEDEF`** –
- **`DECL_UCHAR`** –
- **`DECL_UDT`** –
- **`DECL_UINT`** –
- **`DECL_UINT128`** –
- **`DECL_UINT16`** –
- **`DECL_UINT32`** –
- **`DECL_UINT64`** –
- **`DECL_UNION`** –
- **`DECL_UNKNOWN`** –
- **`DECL_VOID`** –
- **`DECL_VOLATILE`** –
- **`DOUBLE`** –
- **`ENUM`** –
- **`EXT_ARITHMETIC`** –
- **`EXT_INTEGRAL`** –
- **`FLOAT`** –
- **`FLOATING`** –
- **`FUNC`** –
- **`FUNC_PTR`** –
- **`HIGH_LEVEL_FUNC`** –
- **`INT`** –
- **`INT128`** –
- **`INT16`** –
- **`INT32`** –
- **`INT64`** –
- **`INTEGRAL`** –
- **`LDOUBLE`** –
- **`PAF`** –
- **`PARTIAL`** –
- **`POINTER_UNKNOWN`** –
- **`POINTER_VOID`** –
- **`PTR`** –
- **`PTR_OR_ARRAY`** –
- **`PURGING_CALLING_CONVENTION`** –
- **`SCALAR`** –
- **`SHIFTED_PTR`** –
- **`STRUCT`** –
- **`SUE`** –
- **`TBYTE`** –
- **`UCHAR`** –
- **`UDT`** –
- **`UINT`** –
- **`UINT128`** –
- **`UINT16`** –
- **`UINT32`** –
- **`UINT64`** –
- **`UNION`** –
- **`UNKNOWN`** –
- **`USER_CALLING_CONVENTION`** –
- **`VARARG_CALLING_CONVENTION`** –
- **`VARIABLE_STRUCT`** –
- **`VARIABLE_STRUCT_MEMBER`** –
- **`VOID`** –
- **`VOLATILE`** –
- **`WELL_DEFINED`** –

#### ARITHMETIC

```
ARITHMETIC = auto()

```

#### ARRAY

```
ARRAY = auto()

```

#### ATTACHED

```
ATTACHED = auto()

```

#### BITFIELD

```
BITFIELD = auto()

```

#### BOOL

```
BOOL = auto()

```

#### CHAR

```
CHAR = auto()

```

#### COMPLEX

```
COMPLEX = auto()

```

#### CONST

```
CONST = auto()

```

#### CORRECT

```
CORRECT = auto()

```

#### DECL_ARRAY

```
DECL_ARRAY = auto()

```

#### DECL_BITFIELD

```
DECL_BITFIELD = auto()

```

#### DECL_BOOL

```
DECL_BOOL = auto()

```

#### DECL_CHAR

```
DECL_CHAR = auto()

```

#### DECL_COMPLEX

```
DECL_COMPLEX = auto()

```

#### DECL_CONST

```
DECL_CONST = auto()

```

#### DECL_DOUBLE

```
DECL_DOUBLE = auto()

```

#### DECL_ENUM

```
DECL_ENUM = auto()

```

#### DECL_FLOAT

```
DECL_FLOAT = auto()

```

#### DECL_FLOATING

```
DECL_FLOATING = auto()

```

#### DECL_FUNC

```
DECL_FUNC = auto()

```

#### DECL_INT

```
DECL_INT = auto()

```

#### DECL_INT128

```
DECL_INT128 = auto()

```

#### DECL_INT16

```
DECL_INT16 = auto()

```

#### DECL_INT32

```
DECL_INT32 = auto()

```

#### DECL_INT64

```
DECL_INT64 = auto()

```

#### DECL_LAST

```
DECL_LAST = auto()

```

#### DECL_LDOUBLE

```
DECL_LDOUBLE = auto()

```

#### DECL_PAF

```
DECL_PAF = auto()

```

#### DECL_PARTIAL

```
DECL_PARTIAL = auto()

```

#### DECL_PTR

```
DECL_PTR = auto()

```

#### DECL_STRUCT

```
DECL_STRUCT = auto()

```

#### DECL_SUE

```
DECL_SUE = auto()

```

#### DECL_TBYTE

```
DECL_TBYTE = auto()

```

#### DECL_TYPEDEF

```
DECL_TYPEDEF = auto()

```

#### DECL_UCHAR

```
DECL_UCHAR = auto()

```

#### DECL_UDT

```
DECL_UDT = auto()

```

#### DECL_UINT

```
DECL_UINT = auto()

```

#### DECL_UINT128

```
DECL_UINT128 = auto()

```

#### DECL_UINT16

```
DECL_UINT16 = auto()

```

#### DECL_UINT32

```
DECL_UINT32 = auto()

```

#### DECL_UINT64

```
DECL_UINT64 = auto()

```

#### DECL_UNION

```
DECL_UNION = auto()

```

#### DECL_UNKNOWN

```
DECL_UNKNOWN = auto()

```

#### DECL_VOID

```
DECL_VOID = auto()

```

#### DECL_VOLATILE

```
DECL_VOLATILE = auto()

```

#### DOUBLE

```
DOUBLE = auto()

```

#### ENUM

```
ENUM = auto()

```

#### EXT_ARITHMETIC

```
EXT_ARITHMETIC = auto()

```

#### EXT_INTEGRAL

```
EXT_INTEGRAL = auto()

```

#### FLOAT

```
FLOAT = auto()

```

#### FLOATING

```
FLOATING = auto()

```

#### FUNC

```
FUNC = auto()

```

#### FUNC_PTR

```
FUNC_PTR = auto()

```

#### HIGH_LEVEL_FUNC

```
HIGH_LEVEL_FUNC = auto()

```

#### INT

```
INT = auto()

```

#### INT128

```
INT128 = auto()

```

#### INT16

```
INT16 = auto()

```

#### INT32

```
INT32 = auto()

```

#### INT64

```
INT64 = auto()

```

#### INTEGRAL

```
INTEGRAL = auto()

```

#### LDOUBLE

```
LDOUBLE = auto()

```

#### PAF

```
PAF = auto()

```

#### PARTIAL

```
PARTIAL = auto()

```

#### POINTER_UNKNOWN

```
POINTER_UNKNOWN = auto()

```

#### POINTER_VOID

```
POINTER_VOID = auto()

```

#### PTR

```
PTR = auto()

```

#### PTR_OR_ARRAY

```
PTR_OR_ARRAY = auto()

```

#### PURGING_CALLING_CONVENTION

```
PURGING_CALLING_CONVENTION = auto()

```

#### SCALAR

```
SCALAR = auto()

```

#### SHIFTED_PTR

```
SHIFTED_PTR = auto()

```

#### STRUCT

```
STRUCT = auto()

```

#### SUE

```
SUE = auto()

```

#### TBYTE

```
TBYTE = auto()

```

#### UCHAR

```
UCHAR = auto()

```

#### UDT

```
UDT = auto()

```

#### UINT

```
UINT = auto()

```

#### UINT128

```
UINT128 = auto()

```

#### UINT16

```
UINT16 = auto()

```

#### UINT32

```
UINT32 = auto()

```

#### UINT64

```
UINT64 = auto()

```

#### UNION

```
UNION = auto()

```

#### UNKNOWN

```
UNKNOWN = auto()

```

#### USER_CALLING_CONVENTION

```
USER_CALLING_CONVENTION = auto()

```

#### VARARG_CALLING_CONVENTION

```
VARARG_CALLING_CONVENTION = auto()

```

#### VARIABLE_STRUCT

```
VARIABLE_STRUCT = auto()

```

#### VARIABLE_STRUCT_MEMBER

```
VARIABLE_STRUCT_MEMBER = auto()

```

#### VOID

```
VOID = auto()

```

#### VOLATILE

```
VOLATILE = auto()

```

#### WELL_DEFINED

```
WELL_DEFINED = auto()

```

### TypeDetails

```
TypeDetails()

```

Comprehensive type information with category-specific attributes

Methods:

- **`from_tinfo_t`** – Extract all type attributes and details.

Attributes:

- **`array`** (`Optional[ArrayDetails]`) – Get the array type details, if any.
- **`attributes`** (`TypeAttr`) – Get the general type attributes.
- **`bitfield`** (`Optional[BitfieldDetails]`) – Get the bitfield type details, if any.
- **`enum`** (`Optional[EnumDetails]`) – Get the enum type details, if any.
- **`func`** (`Optional[FuncDetails]`) – Get the function type details, if any.
- **`name`** (`str`) – Get the name of the type.
- **`ptr`** (`Optional[PtrDetails]`) – Get the pointer type details, if any.
- **`size`** (`int`) – Get the size of the type.
- **`udt`** (`Optional[UdtDetails]`) – Get the user-defined type details, if any.

#### array

```
array: Optional[ArrayDetails]

```

Get the array type details, if any.

#### attributes

```
attributes: TypeAttr

```

Get the general type attributes.

#### bitfield

```
bitfield: Optional[BitfieldDetails]

```

Get the bitfield type details, if any.

#### enum

```
enum: Optional[EnumDetails]

```

Get the enum type details, if any.

#### func

```
func: Optional[FuncDetails]

```

Get the function type details, if any.

#### name

```
name: str

```

Get the name of the type.

#### ptr

```
ptr: Optional[PtrDetails]

```

Get the pointer type details, if any.

#### size

```
size: int

```

Get the size of the type.

#### udt

```
udt: Optional[UdtDetails]

```

Get the user-defined type details, if any.

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> TypeDetails

```

Extract all type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: Type details object filled with extracted information.

### TypeDetailsVisitor

```
TypeDetailsVisitor(db: Database)

```

Bases: `tinfo_visitor_t`

Visitor class for types. Used to recursively traverse types and gather the type members details. Instances of this class can be passed to the traverse() method to initiate the traversal.

Methods:

- **`visit_type`** –

Attributes:

- **`db`** –
- **`output`** (`list[TypeDetails]`) –

#### db

```
db = db

```

#### output

```
output: list[TypeDetails] = []

```

#### visit_type

```
visit_type(
    out: type_mods_t, tif: tinfo_t, name: str, comment: str
) -> int

```

### TypeFormattingFlags

Bases: `IntFlag`

Type formatting flags used to control type parsing, formatting and printing

Attributes:

- **`HTI_DCL`** – Don't complain about redeclarations
- **`HTI_EXT`** – Debug: print external representation of types
- **`HTI_FIL`** – "Input" is file name, otherwise "input" contains a C declaration
- **`HTI_HIGH`** – Assume high level prototypes (with hidden args, etc)
- **`HTI_INT`** – Debug: print internal representation of types
- **`HTI_LEX`** – Debug: print tokens
- **`HTI_LOWER`** – Lower the function prototypes
- **`HTI_MAC`** – Define macros from the base tils
- **`HTI_NDC`** – Don't decorate names
- **`HTI_NER`** – Ignore all errors but display them
- **`HTI_NOBASE`** – Do not inspect base tils
- **`HTI_NWR`** – No warning messages
- **`HTI_PAK`** – Explicit structure pack value (#pragma pack)
- **`HTI_PAK1`** – pragma pack(1)
- **`HTI_PAK16`** – pragma pack(16)
- **`HTI_PAK2`** – pragma pack(2)
- **`HTI_PAK4`** – pragma pack(4)
- **`HTI_PAK8`** – pragma pack(8)
- **`HTI_PAKDEF`** – Default pack value
- **`HTI_PAK_SHIFT`** – Shift for HTI_PAK. This field should be used if you want to remember
- **`HTI_RAWARGS`** – Leave argument names unchanged (do not remove underscores)
- **`HTI_RELAXED`** – Accept references to unknown namespaces
- **`HTI_SEMICOLON`** – Do not complain if the terminating semicolon is absent
- **`HTI_TST`** – Test mode: discard the result
- **`HTI_UNP`** – Debug: check the result by unpacking it

#### HTI_DCL

```
HTI_DCL = HTI_DCL

```

Don't complain about redeclarations

#### HTI_EXT

```
HTI_EXT = HTI_EXT

```

Debug: print external representation of types

#### HTI_FIL

```
HTI_FIL = HTI_FIL

```

"Input" is file name, otherwise "input" contains a C declaration

#### HTI_HIGH

```
HTI_HIGH = HTI_HIGH

```

Assume high level prototypes (with hidden args, etc)

#### HTI_INT

```
HTI_INT = HTI_INT

```

Debug: print internal representation of types

#### HTI_LEX

```
HTI_LEX = HTI_LEX

```

Debug: print tokens

#### HTI_LOWER

```
HTI_LOWER = HTI_LOWER

```

Lower the function prototypes

#### HTI_MAC

```
HTI_MAC = HTI_MAC

```

Define macros from the base tils

#### HTI_NDC

```
HTI_NDC = HTI_NDC

```

Don't decorate names

#### HTI_NER

```
HTI_NER = HTI_NER

```

Ignore all errors but display them

#### HTI_NOBASE

```
HTI_NOBASE = HTI_NOBASE

```

Do not inspect base tils

#### HTI_NWR

```
HTI_NWR = HTI_NWR

```

No warning messages

#### HTI_PAK

```
HTI_PAK = HTI_PAK

```

Explicit structure pack value (#pragma pack)

#### HTI_PAK1

```
HTI_PAK1 = HTI_PAK1

```

##### pragma pack(1)

#### HTI_PAK16

```
HTI_PAK16 = HTI_PAK16

```

##### pragma pack(16)

#### HTI_PAK2

```
HTI_PAK2 = HTI_PAK2

```

##### pragma pack(2)

#### HTI_PAK4

```
HTI_PAK4 = HTI_PAK4

```

##### pragma pack(4)

#### HTI_PAK8

```
HTI_PAK8 = HTI_PAK8

```

##### pragma pack(8)

#### HTI_PAKDEF

```
HTI_PAKDEF = HTI_PAKDEF

```

Default pack value

#### HTI_PAK_SHIFT

```
HTI_PAK_SHIFT = HTI_PAK_SHIFT

```

Shift for HTI_PAK. This field should be used if you want to remember an explicit pack value for each structure/union type. See HTI_PAK... definitions

#### HTI_RAWARGS

```
HTI_RAWARGS = HTI_RAWARGS

```

Leave argument names unchanged (do not remove underscores)

#### HTI_RELAXED

```
HTI_RELAXED = HTI_RELAXED

```

Accept references to unknown namespaces

#### HTI_SEMICOLON

```
HTI_SEMICOLON = HTI_SEMICOLON

```

Do not complain if the terminating semicolon is absent

#### HTI_TST

```
HTI_TST = HTI_TST

```

Test mode: discard the result

#### HTI_UNP

```
HTI_UNP = HTI_UNP

```

Debug: check the result by unpacking it

### TypeKind

Bases: `Enum`

Type category enumeration.

Attributes:

- **`NAMED`** –
- **`NUMBERED`** –

#### NAMED

```
NAMED = 1

```

#### NUMBERED

```
NUMBERED = 2

```

### TypeManipulationFlags

Bases: `IntFlag`

Flags to be used

Attributes:

- **`NTF_64BIT`** – value is 64bit
- **`NTF_CHKSYNC`** – check that synchronization to IDB passed OK (set_numbered_type, set_named_type)
- **`NTF_COPY`** – save a new type definition, not a typeref
- **`NTF_FIXNAME`** – force-validate the name of the type when setting (set_named_type, set_numbered_type only)
- **`NTF_IDBENC`** – the name is given in the IDB encoding;
- **`NTF_NOBASE`** – don't inspect base tils (for get_named_type)
- **`NTF_NOCUR`** – don't inspect current til file (for get_named_type)
- **`NTF_NO_NAMECHK`** – do not validate type name (set_numbered_type, set_named_type)
- **`NTF_REPLACE`** – replace original type (for set_named_type)
- **`NTF_SYMM`** – symbol, name is mangled ('\_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used
- **`NTF_SYMU`** – symbol, name is unmangled ('func')
- **`NTF_TYPE`** – type name
- **`NTF_UMANGLED`** – name is unmangled (don't use this flag)

#### NTF_64BIT

```
NTF_64BIT = NTF_64BIT

```

value is 64bit

#### NTF_CHKSYNC

```
NTF_CHKSYNC = NTF_CHKSYNC

```

check that synchronization to IDB passed OK (set_numbered_type, set_named_type)

#### NTF_COPY

```
NTF_COPY = NTF_COPY

```

save a new type definition, not a typeref (tinfo_t::set_numbered_type, tinfo_t::set_named_type)

#### NTF_FIXNAME

```
NTF_FIXNAME = NTF_FIXNAME

```

force-validate the name of the type when setting (set_named_type, set_numbered_type only)

#### NTF_IDBENC

```
NTF_IDBENC = NTF_IDBENC

```

the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly (set_named_type, set_numbered_type only)

#### NTF_NOBASE

```
NTF_NOBASE = NTF_NOBASE

```

don't inspect base tils (for get_named_type)

#### NTF_NOCUR

```
NTF_NOCUR = NTF_NOCUR

```

don't inspect current til file (for get_named_type)

#### NTF_NO_NAMECHK

```
NTF_NO_NAMECHK = NTF_NO_NAMECHK

```

do not validate type name (set_numbered_type, set_named_type)

#### NTF_REPLACE

```
NTF_REPLACE = NTF_REPLACE

```

replace original type (for set_named_type)

#### NTF_SYMM

```
NTF_SYMM = NTF_SYMM

```

symbol, name is mangled ('\_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used

#### NTF_SYMU

```
NTF_SYMU = NTF_SYMU

```

symbol, name is unmangled ('func')

#### NTF_TYPE

```
NTF_TYPE = NTF_TYPE

```

type name

#### NTF_UMANGLED

```
NTF_UMANGLED = NTF_UMANGLED

```

name is unmangled (don't use this flag)

### Types

```
Types(database: Database)

```

Bases: `DatabaseEntity`

Provides access to type information and manipulation in the IDA database.

Can be used to iterate over all types in the opened database.

Args: database: Reference to the active IDA database.

Methods:

- **`apply_at`** – Applies a named type to the given address.
- **`copy_type`** – Copies a type and all dependent types from one library to another.
- **`create_library`** – Initializes a new type library.
- **`export_to_library`** – Export all types from local library to external library.
- **`export_type`** – Exports a type and all dependent types from the local (database) library
- **`get_all`** – Retrieves an iterator over all types in the specified type library.
- **`get_at`** – Retrieves the type information of the item at the given address.
- **`get_by_name`** – Retrieve a type information object by name.
- **`get_comment`** – Get comment for type.
- **`get_details`** – Get type details and attributes.
- **`import_from_library`** – Imports the types from an external library to the local (database) library.
- **`import_type`** – Imports a type and all dependent types from an external (loaded) library
- **`load_library`** – Loads a type library file in memory.
- **`parse_declarations`** – Parse type declarations from string and store created types into a library.
- **`parse_header_file`** – Parse type declarations from file and store created types into a library.
- **`parse_one_declaration`** – Parse one declaration from string and create a named type.
- **`save_library`** – Stores the type library to a file.
- **`set_comment`** – Set comment for type.
- **`traverse`** – Traverse the given type using the provided visitor class.
- **`unload_library`** – Unload library (free underlying object).

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### apply_at

```
apply_at(
    type: tinfo_t, ea: ea_t, flags: TypeApplyFlags = GUESSED
) -> bool

```

Applies a named type to the given address.

Args: ea: The effective address. type: The name of the type to apply. flags: Type apply flags.

Returns: True if the type was applied successfully, false otherwise.

Raises: InvalidEAError: If the effective address is invalid.

#### copy_type

```
copy_type(
    source: til_t, destination: til_t, name: str
) -> int

```

Copies a type and all dependent types from one library to another.

Args: source: The source library. destination: The destination library. name: The name of the type.

Raises: RuntimeError: If the copy operation failed.

Returns: The ordinal number of the copied type.

#### create_library

```
create_library(file: Path, description: str) -> til_t

```

Initializes a new type library.

Args: file: The name of the library. description: The description of the library.

Returns: An initialized library.

#### export_to_library

```
export_to_library(library: til_t) -> None

```

Export all types from local library to external library. Numbered types will be automatically enabled for the external library.

Args: library: The destination library.

#### export_type

```
export_type(destination: til_t, name: str) -> int

```

Exports a type and all dependent types from the local (database) library into a loaded (external) library.

Numbered types will be automatically enabled for the external library.

Args: destination: The loaded type library from where to import the type. name: The name of the type.

Raises: RuntimeError: If the export operation failed.

Returns: The ordinal number of the imported type.

#### get_all

```
get_all(
    library: Optional[til_t] = None,
    type_kind: TypeKind = NAMED,
) -> Iterator[tinfo_t]

```

Retrieves an iterator over all types in the specified type library.

Args: library: library instance to iterate over (defaults to local library). type_kind: type kind to iterate over (defaults to 'NAMED').

Returns: A types iterator.

#### get_at

```
get_at(ea: ea_t) -> Optional[tinfo_t]

```

Retrieves the type information of the item at the given address.

Args: ea: The effective address.

Returns: The type information object or None if it does not exist.

Raises: InvalidEAError: If the effective address is invalid.

#### get_by_name

```
get_by_name(
    name: str, library: til_t = None
) -> Optional[tinfo_t]

```

Retrieve a type information object by name.

Args: name: Name of the type to retrieve. library: Type library to retrieve from, defaults to local library.

Returns: The named type information object or None if not found.

#### get_comment

```
get_comment(type_info: tinfo_t) -> str

```

Get comment for type.

Args: type_info: The type info object to get comment from.

Returns: Comment text, or empty string if no comment exists.

#### get_details

```
get_details(type_info: tinfo_t) -> TypeDetails

```

Get type details and attributes.

Args: type_info: The type information object for which to gather details.

Returns: Type details object.

#### import_from_library

```
import_from_library(library: til_t) -> None

```

Imports the types from an external library to the local (database) library.

Args: library: The library instance to import from.

Returns: The status of the add library operation.

#### import_type

```
import_type(source: til_t, name: str) -> int

```

Imports a type and all dependent types from an external (loaded) library into the local (database) library.

Args: source: The loaded type library from where to import the type. name: The name of the type.

Raises: RuntimeError: If the import operation failed.

Returns: The ordinal number of the imported type.

#### load_library

```
load_library(file: Path) -> til_t

```

Loads a type library file in memory.

Args: file: The path of the library file to load. The library name can be passed with or without extension (.til extension will be forced) and as a relative (default ida til directory will be used) or absolute path.

Returns: The loaded til_t object.

#### parse_declarations

```
parse_declarations(
    library: til_t,
    decl: str,
    flags: TypeFormattingFlags = HTI_DCL | HTI_PAKDEF,
) -> int

```

Parse type declarations from string and store created types into a library.

Args: library: The type library into where the parsed types will be stored. decl: C type declarations input string. flags: Optional combination of TypeFormattingFlags.

Returns: Number of parse errors.

#### parse_header_file

```
parse_header_file(
    library: til_t,
    header: Path,
    flags: TypeFormattingFlags = HTI_FIL | HTI_PAKDEF,
) -> int

```

Parse type declarations from file and store created types into a library.

Args: library: The type library into where the parsed types will be stored. header: The path to a header file. flags: Optional combination of TypeFormattingFlags.

Returns: Number of parse errors.

#### parse_one_declaration

```
parse_one_declaration(
    library: til_t,
    decl: str,
    name: str,
    flags: TypeFormattingFlags = HTI_DCL | HTI_PAKDEF,
) -> tinfo_t

```

Parse one declaration from string and create a named type.

Args: library: The type library used for parsing context. decl: C type declaration string to parse. name: The name to assign to the parsed type. flags: Optional combination of TypeFormattingFlags for parsing behavior.

Returns: The tinfo_t instance on success.

Raises: InvalidParameterError: If name/decl is empty, decl cannot be parsed, or name cannot be used to save the declaration.

#### save_library

```
save_library(library: til_t, file: Path) -> bool

```

Stores the type library to a file. If the library contains garbage, it will be collected before storing it. Also compacts the library before saving.

Args: library: The type library instance to save to disk. file: The path to save the library to.

Returns: True if the operation succeeded, False otherwise.

#### set_comment

```
set_comment(type_info: tinfo_t, comment: str) -> bool

```

Set comment for type. This function works only for non-trivial types

Args: type_info: The type info object to set comment for. comment: Comment text to set.

Returns: True if successful, False otherwise.

#### traverse

```
traverse(
    type_info: tinfo_t, visitor: tinfo_visitor_t
) -> None

```

Traverse the given type using the provided visitor class.

Args: type_info: The type information object to visit. visitor: A type visitor subclassed object.

Returns: True if traversal was successful, False otherwise.

#### unload_library

```
unload_library(library: til_t) -> None

```

Unload library (free underlying object).

Args: library: The library instance to unload.

### UdtAttr

Bases: `Flag`

User Defined Type flags

Attributes:

- **`CPP_OBJ`** –
- **`FIXED`** –
- **`MS_STRUCT`** –
- **`TUPLE`** –
- **`UNALIGNED`** –
- **`UNION`** –
- **`VFTABLE`** –

#### CPP_OBJ

```
CPP_OBJ = auto()

```

#### FIXED

```
FIXED = auto()

```

#### MS_STRUCT

```
MS_STRUCT = auto()

```

#### TUPLE

```
TUPLE = auto()

```

#### UNALIGNED

```
UNALIGNED = auto()

```

#### UNION

```
UNION = auto()

```

#### VFTABLE

```
VFTABLE = auto()

```

### UdtDetails

```
UdtDetails()

```

User Defined Type details

Methods:

- **`from_tinfo_t`** – Extract UDT type attributes and details.

Attributes:

- **`attributes`** (`Optional[UdtAttr]`) – Get UDT attributes.
- **`num_members`** (`int`) – Get number of members.

#### attributes

```
attributes: Optional[UdtAttr]

```

Get UDT attributes.

#### num_members

```
num_members: int

```

Get number of members.

#### from_tinfo_t

```
from_tinfo_t(type_info: tinfo_t) -> Optional[UdtDetails]

```

Extract UDT type attributes and details.

Args: type_info: The type information objects for which to extract details.

Returns: UDT type details object filled with extracted information.

# `Xrefs`

## xrefs

Classes:

- **`CallerInfo`** – Information about a function caller.
- **`XrefInfo`** – Enhanced cross-reference information.
- **`XrefType`** – Unified cross-reference types (both code and data).
- **`Xrefs`** – Provides unified access to cross-reference (xref) analysis in the IDA database.
- **`XrefsFlags`** – Flags for xref iteration control.

### CallerInfo

```
CallerInfo(
    ea: ea_t,
    name: str,
    xref_type: XrefType,
    function_ea: Optional[ea_t] = None,
)

```

Information about a function caller.

Attributes:

- **`ea`** (`ea_t`) –
- **`function_ea`** (`Optional[ea_t]`) –
- **`name`** (`str`) –
- **`xref_type`** (`XrefType`) –

#### ea

```
ea: ea_t

```

#### function_ea

```
function_ea: Optional[ea_t] = None

```

#### name

```
name: str

```

#### xref_type

```
xref_type: XrefType

```

### XrefInfo

```
XrefInfo(
    from_ea: ea_t,
    to_ea: ea_t,
    is_code: bool,
    type: XrefType,
    user: bool,
)

```

Enhanced cross-reference information.

Attributes:

- **`from_ea`** (`ea_t`) –
- **`is_call`** (`bool`) – Check if this is a call reference.
- **`is_code`** (`bool`) –
- **`is_flow`** (`bool`) – Check if this is ordinary flow reference.
- **`is_jump`** (`bool`) – Check if this is a jump reference.
- **`is_read`** (`bool`) – Check if this is a data read reference.
- **`is_write`** (`bool`) – Check if this is a data write reference.
- **`to_ea`** (`ea_t`) –
- **`type`** (`XrefType`) –
- **`user`** (`bool`) –

#### from_ea

```
from_ea: ea_t

```

#### is_call

```
is_call: bool

```

Check if this is a call reference.

#### is_code

```
is_code: bool

```

#### is_flow

```
is_flow: bool

```

Check if this is ordinary flow reference.

#### is_jump

```
is_jump: bool

```

Check if this is a jump reference.

#### is_read

```
is_read: bool

```

Check if this is a data read reference.

#### is_write

```
is_write: bool

```

Check if this is a data write reference.

#### to_ea

```
to_ea: ea_t

```

#### type

```
type: XrefType

```

#### user

```
user: bool

```

### XrefType

Bases: `IntEnum`

Unified cross-reference types (both code and data).

Methods:

- **`is_code_ref`** – Check if this is a code reference.
- **`is_data_ref`** – Check if this is a data reference.

Attributes:

- **`CALL_FAR`** – Call Far - creates a function at referenced location
- **`CALL_NEAR`** – Call Near - creates a function at referenced location
- **`INFORMATIONAL`** – Informational reference
- **`JUMP_FAR`** – Jump Far
- **`JUMP_NEAR`** – Jump Near
- **`OFFSET`** – Offset reference or OFFSET flag set
- **`ORDINARY_FLOW`** – Ordinary flow to next instruction
- **`READ`** – Read access
- **`SYMBOLIC`** – Reference to enum member (symbolic constant)
- **`TEXT`** – Text (for forced operands only)
- **`UNKNOWN`** – Unknown
- **`USER_SPECIFIED`** – User specified (obsolete)
- **`WRITE`** – Write access

#### CALL_FAR

```
CALL_FAR = fl_CF

```

Call Far - creates a function at referenced location

#### CALL_NEAR

```
CALL_NEAR = fl_CN

```

Call Near - creates a function at referenced location

#### INFORMATIONAL

```
INFORMATIONAL = dr_I

```

Informational reference

#### JUMP_FAR

```
JUMP_FAR = fl_JF

```

Jump Far

#### JUMP_NEAR

```
JUMP_NEAR = fl_JN

```

Jump Near

#### OFFSET

```
OFFSET = dr_O

```

Offset reference or OFFSET flag set

#### ORDINARY_FLOW

```
ORDINARY_FLOW = fl_F

```

Ordinary flow to next instruction

#### READ

```
READ = dr_R

```

Read access

#### SYMBOLIC

```
SYMBOLIC = dr_S

```

Reference to enum member (symbolic constant)

#### TEXT

```
TEXT = dr_T

```

Text (for forced operands only)

#### UNKNOWN

```
UNKNOWN = 0

```

Unknown

#### USER_SPECIFIED

```
USER_SPECIFIED = fl_USobsolete

```

User specified (obsolete)

#### WRITE

```
WRITE = dr_W

```

Write access

#### is_code_ref

```
is_code_ref() -> bool

```

Check if this is a code reference.

#### is_data_ref

```
is_data_ref() -> bool

```

Check if this is a data reference.

### Xrefs

```
Xrefs(database: Database)

```

Bases: `DatabaseEntity`

Provides unified access to cross-reference (xref) analysis in the IDA database.

This class offers a simplified API for working with both code and data cross-references, with convenient methods for common use cases.

Args: database: Reference to the active IDA database.

Example:

```
# Get all references to an address
for xref in db.xrefs.to(ea):
    print(f"{xref.frm:x} -> {xref.to:x} ({xref.type.name})")

# Get only code references
for caller in db.xrefs.code_refs_to(func_ea):
    print(f"Called from: {caller:x}")

# Get data reads
for reader in db.xrefs.reads_of(data_ea):
    print(f"Read by: {reader:x}")

```

Methods:

- **`calls_from_ea`** – Get addresses called from this address.
- **`calls_to_ea`** – Get addresses where calls to this address occur.
- **`code_refs_from_ea`** – Get code reference addresses from ea.
- **`code_refs_to_ea`** – Get code reference addresses to ea.
- **`data_refs_from_ea`** – Get data reference addresses from ea.
- **`data_refs_to_ea`** – Get data reference addresses to ea.
- **`from_ea`** – Get all cross-references from an address.
- **`get_callers`** – Get detailed caller information for a function.
- **`jumps_from_ea`** – Get addresses jumped to from this address.
- **`jumps_to_ea`** – Get addresses where jumps to this address occur.
- **`reads_of_ea`** – Get addresses that read from this data location.
- **`to_ea`** – Get all cross-references to an address.
- **`writes_to_ea`** – Get addresses that write to this data location.

Attributes:

- **`database`** (`Database`) – Get the database reference, guaranteed to be non-None when called from
- **`m_database`** –

#### database

```
database: Database

```

Get the database reference, guaranteed to be non-None when called from methods decorated with @check_db_open.

Returns: The active database instance.

Note: This property should only be used in methods decorated with @check_db_open, which ensures m_database is not None.

#### m_database

```
m_database = database

```

#### calls_from_ea

```
calls_from_ea(ea: ea_t) -> Iterator[ea_t]

```

Get addresses called from this address.

Args: ea: Source address

Yields: Called addresses

Raises: InvalidEAError: If the effective address is invalid

#### calls_to_ea

```
calls_to_ea(ea: ea_t) -> Iterator[ea_t]

```

Get addresses where calls to this address occur.

Args: ea: Target address

Yields: Addresses containing call instructions

Raises: InvalidEAError: If the effective address is invalid

#### code_refs_from_ea

```
code_refs_from_ea(
    ea: ea_t, flow: bool = True
) -> Iterator[ea_t]

```

Get code reference addresses from ea.

Args: ea: Source address flow: Include ordinary flow references (default: True)

Yields: Target addresses of code references

Raises: InvalidEAError: If the effective address is invalid

#### code_refs_to_ea

```
code_refs_to_ea(
    ea: ea_t, flow: bool = True
) -> Iterator[ea_t]

```

Get code reference addresses to ea.

Args: ea: Target address flow: Include ordinary flow references (default: True)

Yields: Source addresses of code references

Raises: InvalidEAError: If the effective address is invalid

#### data_refs_from_ea

```
data_refs_from_ea(ea: ea_t) -> Iterator[ea_t]

```

Get data reference addresses from ea.

Args: ea: Source address

Yields: Target addresses of data references

Raises: InvalidEAError: If the effective address is invalid

#### data_refs_to_ea

```
data_refs_to_ea(ea: ea_t) -> Iterator[ea_t]

```

Get data reference addresses to ea.

Args: ea: Target address

Yields: Source addresses of data references

Raises: InvalidEAError: If the effective address is invalid

#### from_ea

```
from_ea(
    ea: ea_t, flags: XrefsFlags = ALL
) -> Iterator[XrefInfo]

```

Get all cross-references from an address.

Note: Method named 'from\_' because 'from' is a Python keyword.

Args: ea: Source effective address flags: Filter flags (default: all xrefs)

Yields: XrefInfo objects with detailed xref information

Raises: InvalidEAError: If the effective address is invalid

#### get_callers

```
get_callers(func_ea: ea_t) -> Iterator[CallerInfo]

```

Get detailed caller information for a function.

Args: func_ea: Function start address

Yields: CallerInfo objects with caller details

Raises: InvalidEAError: If the effective address is invalid

#### jumps_from_ea

```
jumps_from_ea(ea: ea_t) -> Iterator[ea_t]

```

Get addresses jumped to from this address.

Args: ea: Source address

Yields: Jump target addresses

Raises: InvalidEAError: If the effective address is invalid

#### jumps_to_ea

```
jumps_to_ea(ea: ea_t) -> Iterator[ea_t]

```

Get addresses where jumps to this address occur.

Args: ea: Target address

Yields: Addresses containing jump instructions

Raises: InvalidEAError: If the effective address is invalid

#### reads_of_ea

```
reads_of_ea(data_ea: ea_t) -> Iterator[ea_t]

```

Get addresses that read from this data location.

Args: data_ea: Data address

Yields: Addresses that read the data

Raises: InvalidEAError: If the effective address is invalid

#### to_ea

```
to_ea(
    ea: ea_t, flags: XrefsFlags = ALL
) -> Iterator[XrefInfo]

```

Get all cross-references to an address.

Args: ea: Target effective address flags: Filter flags (default: all xrefs)

Yields: XrefInfo objects with detailed xref information

Raises: InvalidEAError: If the effective address is invalid

#### writes_to_ea

```
writes_to_ea(data_ea: ea_t) -> Iterator[ea_t]

```

Get addresses that write to this data location.

Args: data_ea: Data address

Yields: Addresses that write to the data

Raises: InvalidEAError: If the effective address is invalid

### XrefsFlags

Bases: `IntFlag`

Flags for xref iteration control.

Methods:

- **`to_ida_flags`** – Convert to IDA's xref flags.

Attributes:

- **`ALL`** – Default - all xrefs
- **`CODE`** – Return only code references
- **`CODE_NOFLOW`** – Code xrefs without flow
- **`DATA`** – Return only data references
- **`NOFLOW`** – Skip ordinary flow xrefs

#### ALL

```
ALL = 0

```

Default - all xrefs

#### CODE

```
CODE = XREF_CODE

```

Return only code references

#### CODE_NOFLOW

```
CODE_NOFLOW = CODE | NOFLOW

```

Code xrefs without flow

#### DATA

```
DATA = XREF_DATA

```

Return only data references

#### NOFLOW

```
NOFLOW = XREF_NOFLOW

```

Skip ordinary flow xrefs

#### to_ida_flags

```
to_ida_flags() -> int

```

Convert to IDA's xref flags.

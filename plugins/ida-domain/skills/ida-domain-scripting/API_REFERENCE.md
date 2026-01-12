# IDA Domain Quick Reference

Quick reference for the IDA Domain API. For basic usage, see [SKILL.md](SKILL.md).

## Table of Contents

- [Database](#database)
- [Analysis](#analysis)
- [Functions](#functions)
- [Segments](#segments)
- [Instructions](#instructions)
- [Bytes](#bytes)
- [Xrefs](#xrefs)
- [Strings](#strings)
- [Names](#names)
- [Types](#types)
- [Comments](#comments)
- [Decompiler](#decompiler)
- [Imports](#imports)
- [Entries](#entries)
- [Search](#search)
- [CallGraph](#callgraph)
- [Heads](#heads)
- [Fixups](#fixups)
- [StackFrames](#stack-frames)
- [Switches](#switches)
- [Problems](#problems)
- [Exporter](#exporter)
- [TryBlocks](#try-blocks)
- [FlowChart](#flowchart)
- [Operands](#operands)
- [Enums Reference](#enums-reference)

---

## Database

The `Database` class is the entry point. In wrapped scripts, `db` is available automatically.

### Opening a Database

```python
# Library mode: open a database file
with Database.open("path/to/file.exe", save_on_close=True) as db:
    print(f"Loaded: {db.path}")

# IDA GUI mode: get current database
db = Database.open()
```

### Database Properties

| Property | Type | Description |
|----------|------|-------------|
| `path` | `str` | Input file path |
| `module` | `str` | Module name (filename) |
| `base_address` | `ea_t` | Image base address |
| `minimum_ea` | `ea_t` | Minimum effective address |
| `maximum_ea` | `ea_t` | Maximum effective address |
| `filesize` | `int` | Input file size in bytes |
| `md5` | `str` | MD5 hash of input file |
| `sha256` | `str` | SHA256 hash of input file |
| `crc32` | `int` | CRC32 checksum |
| `architecture` | `str` | Processor architecture (e.g., "metapc") |
| `bitness` | `int` | Application bitness (32 or 64) |
| `format` | `str` | File format type (e.g., "PE") |
| `load_time` | `str` | Database creation timestamp |
| `execution_mode` | `ExecutionMode` | User or Kernel mode |
| `compiler_information` | `CompilerInformation` | Compiler details |
| `metadata` | `DatabaseMetadata` | All metadata as dataclass |
| `current_ea` | `ea_t` | Current screen address (get/set) |
| `start_ip` | `ea_t` | Start instruction pointer (get/set) |

### Database Methods

```python
# Check if address is valid
if db.is_valid_ea(0x401000):
    print("Address is mapped")

# Save database to new location
db.save_as("analyzed.idb")

# Execute a Python script
db.execute_script("my_script.py")
```

---

## Analysis

Control IDA's auto-analysis engine via `db.analysis`.

```python
# Wait for analysis to complete (most common)
db.analysis.wait()

# Check analysis state
if db.analysis.is_complete:
    print("Analysis finished")

# Analyze a specific range
db.analysis.analyze(0x401000, 0x402000, wait=True)

# Schedule analysis at address
db.analysis.schedule(0x401000, "code")      # or AnalysisType.CODE
db.analysis.schedule(0x401000, "function")  # or AnalysisType.FUNCTION

# Cancel pending analysis
db.analysis.cancel(0x401000, 0x402000)

# Temporarily disable auto-analysis
prev = db.analysis.set_enabled(False)
# ... do batch operations ...
db.analysis.set_enabled(prev)
db.analysis.wait()
```

### AnalysisType Enum

| Value | Description |
|-------|-------------|
| `CODE` | Schedule instruction creation |
| `FUNCTION` | Schedule function creation |
| `REANALYSIS` | Schedule reanalysis |

---

## Functions

Access functions via `db.functions`.

### Iterating Functions

```python
# Iterate all functions
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{name} at 0x{func.start_ea:x}")

# Get function count
print(f"Total functions: {len(db.functions)}")

# Paginated access
page = db.functions.get_page(offset=0, limit=100)

# Chunked processing
for chunk in db.functions.get_chunked(1000):
    process_batch(chunk)
```

### Finding Functions

```python
# Get function at/containing address
func = db.functions.get_at(0x401000)

# Get function by name
func = db.functions.get_function_by_name("main")

# Get functions in range
for func in db.functions.get_between(0x401000, 0x410000):
    print(db.functions.get_name(func))

# Check if function exists
if db.functions.exists_at(0x401000):
    print("Function exists")

# Navigate functions
next_func = db.functions.get_next(0x401000)
prev_func = db.functions.get_previous(0x401000)
```

### Function Properties

```python
func = db.functions.get_at(0x401000)

# Basic info
name = db.functions.get_name(func)
signature = db.functions.get_signature(func)
flags = db.functions.get_flags(func)
comment = db.functions.get_comment(func, repeatable=False)

# Check function attributes
if db.functions.does_return(func):
    print("Function returns")
if db.functions.is_far(func):
    print("Far function")
```

### Function Code

```python
# Get disassembly lines
for line in db.functions.get_disassembly(func):
    print(line)

# Get decompiled pseudocode
for line in db.functions.get_pseudocode(func):
    print(line)

# Get instructions
for insn in db.functions.get_instructions(func):
    print(f"0x{insn.ea:x}: {db.instructions.get_mnemonic(insn)}")

# Get flowchart (basic blocks)
flowchart = db.functions.get_flowchart(func)
for block in flowchart:
    print(f"Block 0x{block.start_ea:x} - 0x{block.end_ea:x}")
```

### Local Variables

```python
# Get all local variables
for lvar in db.functions.get_local_variables(func):
    print(f"{lvar.name}: {lvar.type_str} (arg={lvar.is_argument})")

# Find variable by name
lvar = db.functions.get_local_variable_by_name(func, "buffer")

# Get variable references in pseudocode
refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    print(f"{ref.access_type} at line {ref.line_number}")
```

### Function Relationships

```python
# Get callers (functions that call this one)
for caller in db.functions.get_callers(func):
    print(f"Called by: {db.functions.get_name(caller)}")

# Get callees (functions called by this one)
for callee in db.functions.get_callees(func):
    print(f"Calls: {db.functions.get_name(callee)}")
```

### Modifying Functions

```python
# Rename function
db.functions.set_name(func, "my_function")

# Set comment
db.functions.set_comment(func, "This function does X", repeatable=True)

# Create new function
db.functions.create_at(0x401000)

# Delete function
db.functions.remove(0x401000)

# Force reanalysis
db.functions.reanalyze(func)
```

### FunctionFlags Enum

| Flag | Description |
|------|-------------|
| `NORET` | Function doesn't return |
| `LIB` | Library function |
| `THUNK` | Thunk (jump) function |
| `HIDDEN` | Hidden function chunk |
| `FRAME` | Uses frame pointer |

---

## Segments

Access memory segments via `db.segments`.

### Iterating Segments

```python
for seg in db.segments:
    name = db.segments.get_name(seg)
    size = db.segments.get_size(seg)
    print(f"{name}: 0x{seg.start_ea:x} - 0x{seg.end_ea:x} ({size} bytes)")
```

### Finding Segments

```python
# Get segment containing address
seg = db.segments.get_at(0x401000)

# Get segment by name
seg = db.segments.get_by_name(".text")

# Get by index
seg = db.segments.get_by_index(0)

# Navigation
first = db.segments.get_first()
last = db.segments.get_last()
next_seg = db.segments.get_next(seg)
```

### Segment Properties

```python
name = db.segments.get_name(seg)
size = db.segments.get_size(seg)
bitness = db.segments.get_bitness(seg)      # 16, 32, or 64
seg_class = db.segments.get_class(seg)       # "CODE", "DATA", etc.
seg_type = db.segments.get_type(seg)         # SegmentType enum
comment = db.segments.get_comment(seg)
```

### Modifying Segments

```python
# Rename segment
db.segments.set_name(seg, ".mycode")

# Set class
db.segments.set_class(seg, PredefinedClass.CODE)

# Set permissions
db.segments.set_permissions(seg, SegmentPermissions.READ | SegmentPermissions.EXEC)

# Add/remove permissions
db.segments.add_permissions(seg, SegmentPermissions.WRITE)
db.segments.remove_permissions(seg, SegmentPermissions.WRITE)

# Change bounds
db.segments.set_start(seg, 0x400000)
db.segments.set_end(seg, 0x500000)
```

### Creating/Deleting Segments

```python
# Add new segment
seg = db.segments.add(
    seg_para=0,
    start_ea=0x401000,
    end_ea=0x402000,
    seg_name=".custom",
    seg_class=PredefinedClass.CODE
)

# Delete segment
db.segments.delete(seg, keep_data=False)

# Move segment
result = db.segments.move(seg, to=0x500000)

# Rebase entire program
result = db.segments.rebase(delta=0x10000)
```

### Segment Enums

**SegmentPermissions:**
`NONE`, `READ`, `WRITE`, `EXEC`, `ALL`

**PredefinedClass:**
`CODE`, `DATA`, `CONST`, `STACK`, `BSS`, `XTRN`

**SegmentType:**
`NORM`, `XTRN`, `CODE`, `DATA`, `BSS`

---

## Instructions

Access instructions via `db.instructions`.

### Getting Instructions

```python
# Decode instruction at address
insn = db.instructions.get_at(0x401000)

# Get disassembly text
text = db.instructions.get_disassembly(insn)
mnemonic = db.instructions.get_mnemonic(insn)
size = db.instructions.get_size(0x401000)

# Check if can decode
if db.instructions.can_decode(0x401000):
    insn = db.instructions.get_at(0x401000)
```

### Iterating Instructions

```python
# All instructions in database
for insn in db.instructions:
    print(f"0x{insn.ea:x}: {db.instructions.get_mnemonic(insn)}")

# Instructions in range
for insn in db.instructions.get_between(0x401000, 0x402000):
    print(db.instructions.get_disassembly(insn))

# Paginated/chunked access
page = db.instructions.get_page(offset=0, limit=100)
for chunk in db.instructions.get_chunked(1000):
    process_batch(chunk)
```

### Navigation

```python
insn = db.instructions.get_at(0x401000)
next_insn = db.instructions.get_next(insn.ea)
prev_insn = db.instructions.get_previous(insn.ea)

# Get preceding instruction (following flow)
prev, is_far = db.instructions.get_preceding(0x401100)
```

### Instruction Classification

```python
if db.instructions.is_call_instruction(insn):
    print("This is a call")
if db.instructions.is_indirect_jump_or_call(insn):
    print("Indirect transfer")
if db.instructions.breaks_sequential_flow(insn):
    print("Flow stops here (ret, jmp, etc.)")
```

### Operands

```python
# Get operand count
count = db.instructions.get_operands_count(insn)

# Get specific operand (returns Operand object)
op = db.instructions.get_operand(insn, 0)
if op:
    print(f"Type: {op.type}, Value: {op.get_value()}")

# Get all operands
for op in db.instructions.get_operands(insn):
    print(f"Operand {op.number}: {op.type}")

# Format operand as text
text = db.instructions.format_operand(insn.ea, 0)
```

### Creating Instructions

```python
# Convert bytes to instruction
db.instructions.create_at(0x401000)
```

---

## Bytes

Access raw memory via `db.bytes`.

### Reading Data

```python
# Read single values
byte_val = db.bytes.get_byte_at(0x401000)
word_val = db.bytes.get_word_at(0x401000)
dword_val = db.bytes.get_dword_at(0x401000)
qword_val = db.bytes.get_qword_at(0x401000)
float_val = db.bytes.get_float_at(0x401000)
double_val = db.bytes.get_double_at(0x401000)

# Read multiple bytes
data = db.bytes.get_bytes_at(0x401000, size=16)

# Read strings
string = db.bytes.get_string_at(0x401000)
cstring = db.bytes.get_cstring_at(0x401000, max_length=256)
```

### Writing/Patching Data

```python
# Set values (direct write)
db.bytes.set_byte_at(0x401000, 0x90)
db.bytes.set_bytes_at(0x401000, b"\x90\x90\x90")

# Patch values (saves originals for reverting)
db.bytes.patch_byte_at(0x401000, 0x90)
db.bytes.patch_bytes_at(0x401000, b"\x90\x90\x90")

# Revert patches
db.bytes.revert_byte_at(0x401000)

# Get original values
orig = db.bytes.get_original_byte_at(0x401000)
```

### Searching

```python
# Find byte pattern
addr = db.bytes.find_bytes_between(b"\x55\x8B\xEC", 0x401000, 0x410000)

# Find with wildcards (IDA pattern syntax)
addr = db.bytes.find_pattern("55 8B EC ?? ?? 90", 0x401000, 0x410000)
all_matches = db.bytes.find_pattern_all("CC ?? 90", 0x401000, 0x410000)

# Find text
addr = db.bytes.find_text_between("error", 0x401000, 0x410000)

# Find immediate value in instructions
addr = db.bytes.find_immediate_between(0x12345678, 0x401000, 0x410000)
```

### Type Checking

```python
if db.bytes.is_code_at(0x401000):
    print("Contains code")
if db.bytes.is_data_at(0x401000):
    print("Contains data")
if db.bytes.is_unknown_at(0x401000):
    print("Undefined bytes")
if db.bytes.is_head_at(0x401000):
    print("Start of an item")
```

### Creating Data Items

```python
db.bytes.create_byte_at(0x401000, count=4)
db.bytes.create_dword_at(0x401000)
db.bytes.create_string_at(0x401000, length=10, string_type=StringType.C)
db.bytes.create_struct_at(0x401000, count=1, tid=struct_id)
```

### Item Navigation

```python
head = db.bytes.get_item_head_at(0x401002)  # Get start of item
end = db.bytes.get_item_end_at(0x401000)     # Get end of item
size = db.bytes.get_item_size_at(0x401000)

next_head = db.bytes.get_next_head(0x401000)
prev_head = db.bytes.get_previous_head(0x401000)
```

---

## Xrefs

Access cross-references via `db.xrefs`.

### Getting References TO an Address

```python
# All references to address (returns XrefInfo objects)
for xref in db.xrefs.to_ea(0x401000):
    print(f"From 0x{xref.from_ea:x}, type: {xref.type}")

# Code references only
for addr in db.xrefs.code_refs_to_ea(0x401000, flow=False):
    print(f"Code ref from 0x{addr:x}")

# Data references only
for addr in db.xrefs.data_refs_to_ea(0x401000):
    print(f"Data ref from 0x{addr:x}")

# Specific reference types
for addr in db.xrefs.calls_to_ea(0x401000):
    print(f"Called from 0x{addr:x}")
for addr in db.xrefs.jumps_to_ea(0x401000):
    print(f"Jump from 0x{addr:x}")
```

### Getting References FROM an Address

```python
# All references from address
for xref in db.xrefs.from_ea(0x401000):
    print(f"To 0x{xref.to_ea:x}, type: {xref.type}")

# Code references from address
for addr in db.xrefs.code_refs_from_ea(0x401000):
    print(f"Code ref to 0x{addr:x}")

# Calls from address
for addr in db.xrefs.calls_from_ea(0x401000):
    print(f"Calls 0x{addr:x}")
```

### Data Access References

```python
# Who reads this data?
for addr in db.xrefs.reads_of_ea(0x404000):
    print(f"Read at 0x{addr:x}")

# Who writes this data?
for addr in db.xrefs.writes_to_ea(0x404000):
    print(f"Write at 0x{addr:x}")
```

### Checking References

```python
if db.xrefs.has_any_refs_to(0x401000):
    print("Has incoming references")
if db.xrefs.has_code_refs_to(0x401000):
    print("Has code references")

count = db.xrefs.count_refs_to(0x401000)
```

### LLM-Friendly Unified Interface

```python
# Unified interface with string kinds
for xref in db.xrefs.get_refs_to(0x401000, kind="all"):
    print(xref)
for addr in db.xrefs.get_refs_to(0x401000, kind="calls"):
    print(f"0x{addr:x}")

# Valid kinds: "all", "code", "data", "calls", "jumps", "reads", "writes"
```

### Getting Caller Info

```python
for caller in db.xrefs.get_callers(0x401000):
    print(f"Called from {caller.name} at 0x{caller.ea:x}")
```

### Modifying References

```python
# Add cross-reference
db.xrefs.add_code_xref(from_ea, to_ea, XrefType.CALL_NEAR)
db.xrefs.add_data_xref(from_ea, to_ea, XrefType.READ)

# Delete cross-reference
db.xrefs.delete_xref(from_ea, to_ea)
```

### XrefType Enum

**Code References:**
`CALL_FAR`, `CALL_NEAR`, `JUMP_FAR`, `JUMP_NEAR`, `ORDINARY_FLOW`

**Data References:**
`OFFSET`, `READ`, `WRITE`, `TEXT`, `INFORMATIONAL`

---

## Strings

Access extracted strings via `db.strings`.

### Iterating Strings

```python
for s in db.strings:
    print(f"0x{s.address:x}: {str(s)}")

# Total count
print(f"Found {len(db.strings)} strings")

# By index
first_string = db.strings[0]
```

### Finding Strings

```python
# Get string at address
s = db.strings.get_at(0x404000)
if s:
    print(f"String: {str(s)}, Length: {s.length}")

# Get by index
s = db.strings.get_by_index(5)
```

### StringItem Properties

```python
s = db.strings.get_at(0x404000)
print(f"Address: 0x{s.address:x}")
print(f"Length: {s.length}")
print(f"Type: {s.type}")           # StringType enum
print(f"Encoding: {s.encoding}")
print(f"Contents: {s.contents}")    # bytes
print(f"Text: {str(s)}")            # decoded string
```

### Paginated Access

```python
# Get page of strings
page = db.strings.get_page(offset=0, limit=25)

# Process in chunks
for chunk in db.strings.get_chunked(100):
    for s in chunk:
        process(s)

# Get strings in range
for s in db.strings.get_between(0x404000, 0x405000):
    print(str(s))
```

### Rebuilding String List

```python
from ida_domain.strings import StringListConfig, StringType

config = StringListConfig(
    string_types=[StringType.C, StringType.C_16],
    min_len=4,
    only_ascii_7bit=False
)
db.strings.rebuild(config)
```

---

## Names

Access symbols and labels via `db.names`.

### Iterating Names

```python
for ea, name in db.names:
    print(f"0x{ea:x}: {name}")

# Count
print(f"Total names: {len(db.names)}")
```

### Getting Names

```python
# Get name at address
name = db.names.get_at(0x401000)

# Get visible name (as shown in disassembly)
visible = db.names.get_visible_name(0x401000)

# Resolve name to address
addr = db.names.resolve_name("main")
```

### Setting Names

```python
# Set name
db.names.set_name(0x401000, "my_function")

# Force name (tries variations if exists)
db.names.force_name(0x401000, "my_function")

# Delete name
db.names.delete_at(0x401000)
```

### Name Properties

```python
# Check name type
if db.names.is_public_name(0x401000):
    print("Public symbol")
if db.names.is_weak_name(0x401000):
    print("Weak symbol")

# Modify properties
db.names.make_name_public(0x401000)
db.names.make_name_non_public(0x401000)
```

### Demangling

```python
# Get demangled name
demangled = db.names.get_demangled_name(0x401000)

# Demangle a string
demangled = db.names.demangle_name("_ZN3Foo3barEv")
```

### Validation

```python
# Check if valid name
if db.names.is_valid_name("my_var"):
    print("Valid")

# Validate and clean
is_valid, cleaned = db.names.validate("my-var")
```

---

## Types

Access type information via `db.types`.

### Getting Types

```python
# By name
tinfo = db.types.get_by_name("HWND")

# At address
tinfo = db.types.get_at(0x401000)

# By ordinal
tinfo = db.types.get_by_ordinal(5)

# Guess type at address
tinfo = db.types.guess_at(0x401000)

# LLM-friendly unified interface
tinfo = db.types.get("size_t", by="name")
tinfo = db.types.get(0x401000, by="address")
```

### Applying Types

```python
# Apply by name
db.types.apply_by_name(0x401000, "HWND")

# Apply from declaration
db.types.apply_declaration(0x401000, "int *")

# Apply tinfo object
db.types.apply_at(0x401000, tinfo)

# LLM-friendly unified interface
db.types.apply(0x401000, "HWND", by="name")
db.types.apply(0x401000, "int *", by="decl")
```

### Type Information

```python
# Format as C declaration
decl = db.types.format_type(tinfo)

# Get detailed info
details = db.types.get_details(tinfo)
print(f"Name: {details.name}, Size: {details.size}")

# Check type category
if db.types.is_struct(tinfo):
    print("Structure type")
if db.types.is_enum(tinfo):
    print("Enum type")
```

### Parsing Types

```python
# Parse single declaration
tinfo = db.types.parse_one_declaration(library, "struct Foo { int x; };", "Foo")

# Parse multiple declarations
count = db.types.parse_declarations(library, "typedef int BOOL; typedef void* HANDLE;")

# Parse header file
count = db.types.parse_header_file(library, Path("myheader.h"))
```

### Type Libraries

```python
# Load library
lib = db.types.load_library(Path("windows.til"))

# Import types from library
db.types.import_from_library(lib)

# Unload
db.types.unload_library(lib)
```

---

## Comments

Access comments via `db.comments`.

### Regular Comments

```python
# Get comment at address
info = db.comments.get_at(0x401000)
if info:
    print(f"Comment: {info.comment}")

# Set comment
db.comments.set_at(0x401000, "This is important")

# Set repeatable comment
db.comments.set_at(0x401000, "Shows everywhere", CommentKind.REPEATABLE)

# Delete comment
db.comments.delete_at(0x401000)
```

### Iterating Comments

```python
for info in db.comments:
    print(f"0x{info.ea:x}: {info.comment}")

# Get specific type
for info in db.comments.get_all(CommentKind.REPEATABLE):
    print(info.comment)
```

### Extra Comments (Multi-line)

```python
# Add multi-line comment before code
idx = db.comments.get_first_free_extra_index(0x401000, ExtraCommentKind.ANTERIOR)
db.comments.set_extra_at(0x401000, idx, "Line 1", ExtraCommentKind.ANTERIOR)
db.comments.set_extra_at(0x401000, idx+1, "Line 2", ExtraCommentKind.ANTERIOR)

# Get all extra comments
for line in db.comments.get_all_extra_at(0x401000, ExtraCommentKind.ANTERIOR):
    print(line)

# Delete
db.comments.delete_all_extra_at(0x401000, ExtraCommentKind.ANTERIOR)
```

---

## Decompiler

Access Hex-Rays decompiler via `db.decompiler`.

```python
# Check availability
if db.decompiler.is_available:
    # Decompile function
    lines = db.decompiler.decompile(0x401000)
    if lines:
        for line in lines:
            print(line)
```

---

## Imports

Access import table via `db.imports`.

### Iterating Imports

```python
# Iterate modules
for module in db.imports:
    print(f"{module.name}: {module.import_count} imports")
    for entry in module.imports:
        print(f"  {entry.full_name}")

# Iterate all entries directly
for entry in db.imports.get_all_entries():
    print(f"0x{entry.address:x}: {entry.full_name}")
```

### Finding Imports

```python
# By name
entry = db.imports.get_by_name("VirtualAlloc")
entry = db.imports.get_by_name("VirtualAlloc", module_name="kernel32.dll")

# By address
entry = db.imports.get_at(0x401000)

# Search with regex
for entry in db.imports.search_by_pattern(r'^Create'):
    print(entry.full_name)
```

### Import Information

```python
# Check if address is import
if db.imports.is_import(0x401000):
    print("This is an import entry")

# Get statistics
stats = db.imports.get_statistics()
print(f"Modules: {stats.module_count}, Total: {stats.total_imports}")
```

---

## Entries

Access entry points via `db.entries`.

```python
# Iterate all entries
for entry in db.entries:
    print(f"{entry.name} at 0x{entry.address:x}")

# Count
print(f"Total entries: {len(db.entries)}")

# Find by name
entry = db.entries.get_by_name("main")

# Find by ordinal
entry = db.entries.get_by_ordinal(1)

# Add new entry
db.entries.add(0x401000, "my_entry")
```

---

## Search

Find addresses by criteria via `db.search`.

### Unified Search Interface

```python
# Find next of type
addr = db.search.find_next(0x401000, "undefined", direction="down")
addr = db.search.find_next(0x401000, "code")
addr = db.search.find_next(0x401000, "data")
addr = db.search.find_next(0x401000, "code_outside_function")

# Find all in range
for addr in db.search.find_all(0x401000, 0x410000, "undefined"):
    print(f"Undefined at 0x{addr:x}")
```

### Specific Search Methods

```python
# State-based
addr = db.search.next_undefined(0x401000)
addr = db.search.next_defined(0x401000)

# Type-based
addr = db.search.next_code(0x401000)
addr = db.search.next_data(0x401000)

# Iterators
for addr in db.search.all_undefined(0x401000, 0x410000):
    print(f"0x{addr:x}")
for addr in db.search.all_code_outside_functions():
    print(f"Orphan code at 0x{addr:x}")
```

### Problem Search

```python
# Find errors
addr, op = db.search.next_error(0x401000)
addr, op = db.search.next_untyped_operand(0x401000)

# Iterate all errors
for addr, op in db.search.all_errors():
    print(f"Error at 0x{addr:x}, operand {op}")
```

---

## CallGraph

Multi-hop call graph traversal via `db.callgraph`.

```python
# Get callers (direct and transitive)
for caller in db.callgraph.callers_of(func_ea, max_depth=3):
    print(f"Caller: 0x{caller:x}")

# Get callees (functions called)
for callee in db.callgraph.callees_of(func_ea, max_depth=3):
    print(f"Callee: 0x{callee:x}")

# Find call paths between functions
for path in db.callgraph.paths_between(src_ea, dst_ea, max_depth=10):
    print(path)  # CallPath(0x401000 -> 0x401100 -> 0x401200)

# Get all reachable functions
reachable = db.callgraph.reachable_from(func_ea)

# Get all functions that can reach this one
callers = db.callgraph.reaches(func_ea)
```

---

## Heads

Iterate over items (instructions/data) via `db.heads`.

```python
# Iterate all heads
for ea in db.heads:
    if db.heads.is_code(ea):
        print(f"Code at 0x{ea:x}")

# Get heads in range
for ea in db.heads.get_between(0x401000, 0x402000):
    size = db.heads.get_size(ea)
    print(f"0x{ea:x}: {size} bytes")

# Navigation
next_ea = db.heads.get_next(0x401000)
prev_ea = db.heads.get_previous(0x401000)

# Check type
if db.heads.is_head(0x401000):
    print("Start of item")
```

---

## Fixups

Manage relocations via `db.fixups`.

```python
# Get fixup at address
fixup = db.fixups.get_at(0x401000)
if fixup:
    print(f"Target: 0x{fixup.target:x}, Type: {fixup.type}")

# Check for fixup
if db.fixups.has_fixup(0x401000):
    print("Has relocation")

# Iterate fixups
for fixup in db.fixups.get_all():
    print(f"0x{fixup.address:x} -> 0x{fixup.target:x}")

# Add fixup
db.fixups.add(0x401000, FixupType.OFF32, target_offset=0x402000)
```

---

## Stack Frames

Manage function stack frames via `db.stack_frames`.

```python
# Get frame for function
frame = db.stack_frames.get_at(func_ea)
if frame:
    print(f"Frame size: {frame.size}")
    print(f"Locals: {frame.local_size}, Args: {frame.argument_size}")

    # Iterate variables
    for var in frame.variables:
        print(f"  {var.name}: offset {var.offset}, size {var.size}")

# Define new variable
db.stack_frames.define_variable(func_ea, "buffer", -0x40, "char[64]")

# Rename variable
db.stack_frames.rename_variable(func_ea, -0x40, "my_buffer")
```

---

## Switches

Analyze switch statements via `db.switches`.

```python
# Get switch at address
switch = db.switches.get_at(0x401000)
if switch:
    print(f"Cases: {switch.ncases}")

    # Get jump targets
    targets = db.switches.get_jump_table_addresses(switch)
    for target in targets:
        print(f"  Target: 0x{target:x}")

    # Get case values
    values = db.switches.get_case_values(switch)
```

---

## Problems

Track analysis issues via `db.problems`.

```python
# Get all problems
for problem in db.problems.get_all():
    print(f"0x{problem.address:x}: {problem.type_name}")

# Get problems of specific type
for problem in db.problems.get_all(ProblemType.NONAME):
    print(f"Missing name at 0x{problem.address:x}")

# Check for problem
if db.problems.has_problem(0x401000):
    print("Has problem")

# Count by type
count = db.problems.count_by_type(ProblemType.BADSTACK)
```

---

## Exporter

Export analysis results via `db.exporter`.

```python
# Export to various formats
db.exporter.export("output.map", ExportFormat.MAP)
db.exporter.export("output.asm", ExportFormat.ASM)
db.exporter.export("output.lst", ExportFormat.LST)

# Export specific range
db.exporter.export_range("output.asm", 0x401000, 0x402000, ExportFormat.ASM)

# Export raw bytes
db.exporter.export_bytes("output.bin", 0x401000, 0x402000)
```

---

## Try Blocks

Analyze exception handling via `db.try_blocks`.

```python
# Get try blocks in range
for block in db.try_blocks.get_in_range(0x401000, 0x410000):
    print(f"Try: 0x{block.start_ea:x} - 0x{block.end_ea:x}")
    if block.is_cpp:
        for catch in block.catches:
            print(f"  Catch: 0x{catch.start_ea:x}")
    elif block.is_seh:
        print(f"  SEH handler: 0x{block.seh_handler.start_ea:x}")

# Check if address is in try block
if db.try_blocks.is_in_try_block(0x401000):
    print("Inside try block")
```

---

## FlowChart

Analyze control flow via `db.functions.get_flowchart()`.

```python
func = db.functions.get_at(0x401000)
flowchart = db.functions.get_flowchart(func)

for block in flowchart:
    print(f"Block 0x{block.start_ea:x} - 0x{block.end_ea:x}")
    print(f"  Successors: {block.count_successors()}")
    print(f"  Predecessors: {block.count_predecessors()}")

    for succ in block.get_successors():
        print(f"  -> 0x{succ.start_ea:x}")

    for insn in block.get_instructions():
        print(f"    0x{insn.ea:x}")
```

---

## Operands

Detailed operand analysis (via `db.instructions.get_operand()`).

```python
insn = db.instructions.get_at(0x401000)
for op in db.instructions.get_operands(insn):
    print(f"Operand {op.number}:")
    print(f"  Type: {op.type}")
    print(f"  Size: {op.size_bytes} bytes")
    print(f"  Access: {op.get_access_type()}")

    if op.type == OperandType.REGISTER:
        print(f"  Register: {op.get_register_name()}")
    elif op.type == OperandType.IMMEDIATE:
        print(f"  Value: {op.get_value()}")
    elif op.type == OperandType.MEMORY:
        print(f"  Address: 0x{op.get_address():x}")
```

---

## Enums Reference

### XrefType

```python
from ida_domain.xrefs import XrefType

# Code references
XrefType.CALL_NEAR    # Near call
XrefType.CALL_FAR     # Far call
XrefType.JUMP_NEAR    # Near jump
XrefType.JUMP_FAR     # Far jump
XrefType.ORDINARY_FLOW # Sequential flow

# Data references
XrefType.OFFSET       # Offset reference
XrefType.READ         # Read access
XrefType.WRITE        # Write access
```

### StringType

```python
from ida_domain.strings import StringType

StringType.C          # C-style null-terminated
StringType.C_16       # C-style 16-bit (Unicode)
StringType.PASCAL     # Pascal-style with length prefix
```

### SegmentPermissions

```python
from ida_domain.segments import SegmentPermissions

SegmentPermissions.READ
SegmentPermissions.WRITE
SegmentPermissions.EXEC
SegmentPermissions.ALL  # READ | WRITE | EXEC
```

### FunctionFlags

```python
from ida_domain.functions import FunctionFlags

FunctionFlags.NORET     # Doesn't return
FunctionFlags.LIB       # Library function
FunctionFlags.THUNK     # Thunk function
FunctionFlags.FRAME     # Uses frame pointer
```

### OperandType

```python
from ida_domain.operands import OperandType

OperandType.VOID
OperandType.REGISTER
OperandType.MEMORY
OperandType.IMMEDIATE
OperandType.NEAR_ADDRESS
OperandType.FAR_ADDRESS
```

### SearchTarget

```python
from ida_domain.search import SearchTarget

SearchTarget.UNDEFINED
SearchTarget.DEFINED
SearchTarget.CODE
SearchTarget.DATA
SearchTarget.CODE_OUTSIDE_FUNCTION
```

### ProblemType

```python
from ida_domain.problems import ProblemType

ProblemType.NONAME     # Missing name
ProblemType.BADSTACK   # Stack analysis issue
ProblemType.ATTN       # Needs attention
ProblemType.NOBASE     # Missing base
```

### CommentKind

```python
from ida_domain.comments import CommentKind

CommentKind.REGULAR    # Regular comment
CommentKind.REPEATABLE # Repeatable comment
CommentKind.ALL        # Both types
```

---

## Quick Tips

1. **Always wait for analysis**: Call `db.analysis.wait()` before querying results after modifications.

2. **Use iterators for large datasets**: Methods like `get_all()` return iterators to avoid memory issues.

3. **Check for None**: Most `get_*` methods return `None` if not found rather than raising exceptions.

4. **Use unified interfaces**: Methods like `db.xrefs.get_refs_to(ea, kind="calls")` are LLM-friendly.

5. **Batch operations**: Use `get_chunked()` for processing with progress updates.

6. **Address validation**: Use `db.is_valid_ea(ea)` before operations on untrusted addresses.

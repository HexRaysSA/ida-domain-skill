"""
Exercise 11: Vtable Discovery + Class Layout Approximation

This script automatically locates C++ vtables and reconstructs class information:
1. Locates vtables by scanning .rodata for pointer arrays
2. Identifies virtual methods from vtable entries
3. Groups methods into classes using RTTI if available
4. Detects inheritance relationships by vtable prefix similarity
"""

import ida_bytes
import ida_name
import ida_segment
import ida_funcs
import ida_idaapi
from ida_idaapi import BADADDR


def is_code_pointer(ea, min_ea, max_ea):
    """Check if the value at ea is a pointer to code."""
    # Read pointer (assume 64-bit)
    ptr = db.bytes.get_qword_at(ea)
    if ptr == 0 or ptr == BADADDR:
        return False, None
    if ptr < min_ea or ptr >= max_ea:
        return False, None
    # Check if it points to code
    if db.bytes.is_code_at(ptr):
        return True, ptr
    return False, None


def find_vtables():
    """Find all vtables in the binary."""
    vtables = []

    # Get code segment bounds for pointer validation
    code_min = db.minimum_ea
    code_max = db.maximum_ea

    # Find .rodata or similar read-only data segments
    rodata_segments = []
    for seg in db.segments:
        name = db.segments.get_name(seg)
        # Look for read-only data segments
        if name in ['.rodata', '__const', '.rdata', '.data.rel.ro', '__DATA_CONST']:
            rodata_segments.append(seg)
        # Also check segment class
        seg_class = db.segments.get_class(seg)
        if seg_class and 'CONST' in seg_class.upper() and seg not in rodata_segments:
            rodata_segments.append(seg)

    # If no rodata found, try data segments
    if not rodata_segments:
        for seg in db.segments:
            name = db.segments.get_name(seg)
            if name in ['.data', '__DATA', '__data']:
                rodata_segments.append(seg)

    print(f"Scanning {len(rodata_segments)} data segment(s) for vtables...")

    # Scan each segment for pointer arrays
    for seg in rodata_segments:
        seg_name = db.segments.get_name(seg)
        print(f"  Scanning segment: {seg_name} (0x{seg.start_ea:x} - 0x{seg.end_ea:x})")

        ea = seg.start_ea
        ptr_size = 8  # 64-bit pointers

        while ea + ptr_size <= seg.end_ea:
            # Check if this could be the start of a vtable
            # A vtable typically starts with function pointers

            # Skip if not aligned
            if ea % ptr_size != 0:
                ea += 1
                continue

            # Check if we have a name at this address (might indicate vtable)
            name_at_ea = db.names.get_at(ea)
            is_vtable_name = name_at_ea and ('vtable' in name_at_ea.lower() or
                                              '_ZTV' in name_at_ea or
                                              '??_7' in name_at_ea)  # MSVC vtable prefix

            # Try to find consecutive function pointers
            method_ptrs = []
            scan_ea = ea

            # RTTI check: in Itanium ABI, vtable has offset and typeinfo before methods
            # Layout: [offset-to-top, typeinfo-ptr, vmethod1, vmethod2, ...]
            # Check for possible RTTI prefix
            rtti_offset = 0
            typeinfo_ptr = None

            # Read potential offset-to-top (should be 0 for primary vtable)
            try:
                offset_to_top = db.bytes.get_qword_at(ea)
                if offset_to_top == 0:
                    # Check next qword for typeinfo pointer
                    potential_typeinfo = db.bytes.get_qword_at(ea + ptr_size)
                    if potential_typeinfo != 0 and potential_typeinfo != BADADDR:
                        # Check if it points to valid memory
                        if code_min <= potential_typeinfo < code_max:
                            typeinfo_ptr = potential_typeinfo
                            rtti_offset = 2 * ptr_size  # Skip offset and typeinfo
            except:
                pass

            scan_ea = ea + rtti_offset

            while scan_ea + ptr_size <= seg.end_ea:
                is_code, ptr = is_code_pointer(scan_ea, code_min, code_max)
                if is_code:
                    method_ptrs.append((scan_ea, ptr))
                    scan_ea += ptr_size
                else:
                    break

            # A vtable needs at least 2 methods (destructor + at least one virtual)
            min_methods = 2
            if len(method_ptrs) >= min_methods or (is_vtable_name and len(method_ptrs) >= 1):
                vtables.append({
                    'ea': ea,
                    'name': name_at_ea,
                    'methods': method_ptrs,
                    'rtti_offset': rtti_offset,
                    'typeinfo_ptr': typeinfo_ptr,
                    'size': rtti_offset + len(method_ptrs) * ptr_size
                })
                # Skip past this vtable
                ea = scan_ea
            else:
                ea += ptr_size

    return vtables


def parse_mangled_class_name(mangled):
    """Parse mangled class name to extract readable name.

    Itanium ABI mangling: numbers prefix the length of the following name.
    E.g., '6Circle' means a 6-character name 'Circle'
    """
    if not mangled:
        return None

    # Skip any leading characters until we find a digit
    i = 0
    while i < len(mangled) and not mangled[i].isdigit():
        i += 1

    if i >= len(mangled):
        return mangled

    # Parse length-prefixed names
    result_parts = []
    while i < len(mangled):
        # Read the length
        length_str = ''
        while i < len(mangled) and mangled[i].isdigit():
            length_str += mangled[i]
            i += 1

        if not length_str:
            break

        length = int(length_str)
        if i + length <= len(mangled):
            name_part = mangled[i:i+length]
            result_parts.append(name_part)
            i += length
        else:
            break

    if result_parts:
        return '::'.join(result_parts)
    return mangled


def extract_class_name_from_rtti(typeinfo_ptr):
    """Try to extract class name from RTTI typeinfo pointer."""
    if typeinfo_ptr is None or typeinfo_ptr == BADADDR:
        return None

    try:
        # In Itanium ABI, typeinfo structure contains:
        # - vtable ptr to std::type_info
        # - pointer to mangled name string
        name_ptr = db.bytes.get_qword_at(typeinfo_ptr + 8)
        if name_ptr and name_ptr != BADADDR:
            # Read the mangled name string
            mangled = db.bytes.get_cstring_at(name_ptr, 256)
            if mangled:
                # Try to demangle using IDA
                demangled = db.names.demangle_name(mangled)
                if demangled and demangled != mangled:
                    return demangled
                # Parse manually if IDA demangling fails
                return parse_mangled_class_name(mangled)
    except:
        pass

    return None


def extract_class_name_from_vtable_name(vtable_name):
    """Extract class name from vtable symbol name."""
    if not vtable_name:
        return None

    # Try to demangle
    demangled = db.names.demangle_name(vtable_name)
    if demangled:
        # Remove "vtable for " prefix
        if 'vtable for ' in demangled:
            return demangled.replace('vtable for ', '')
        if '`vtable\'' in demangled:
            return demangled.replace('`vtable\'', '').strip()
        return demangled

    # Handle mangled names
    if '_ZTV' in vtable_name:
        # Itanium ABI: _ZTV<length><name>
        idx = vtable_name.index('_ZTV') + 4
        return parse_mangled_class_name(vtable_name[idx:])

    return vtable_name


def get_function_name(func_ea):
    """Get function name at address."""
    name = db.names.get_at(func_ea)
    if name:
        # Try to demangle
        demangled = db.names.demangle_name(name)
        return demangled if demangled else name
    return f"sub_{func_ea:x}"


def get_short_method_name(full_name, class_name):
    """Get shortened method name by removing class prefix if present."""
    if class_name and full_name.startswith(class_name + '::'):
        return full_name[len(class_name) + 2:]
    return full_name


def detect_inheritance(vtables):
    """Detect inheritance relationships by comparing vtable structures.

    Uses a scoring system based on:
    1. Shared method addresses (inherited methods not overridden)
    2. Method slot count differences
    3. Class name similarity (e.g., SerializableCircle contains Circle)
    """
    inheritance = {}

    # Skip thunk tables (they're part of MI implementation, not separate classes)
    main_vtables = [vt for vt in vtables if vt.get('typeinfo_ptr') is not None]

    # Compare vtables to find inheritance
    for derived_vt in main_vtables:
        derived_methods = derived_vt['methods']
        derived_count = len(derived_methods)
        derived_name = derived_vt.get('class_name', '')

        best_base = None
        best_score = -1

        for base_vt in main_vtables:
            if base_vt['ea'] == derived_vt['ea']:
                continue

            base_methods = base_vt['methods']
            base_count = len(base_methods)
            base_name = base_vt.get('class_name', '')

            # Base class should have fewer methods
            if base_count >= derived_count:
                continue

            # Calculate inheritance score
            score = 0

            # Count shared method addresses (non-overridden inherited methods)
            shared_methods = 0
            for i, (_, base_ptr) in enumerate(base_methods):
                if i < len(derived_methods):
                    _, derived_ptr = derived_methods[i]
                    if base_ptr == derived_ptr:
                        shared_methods += 1

            # Higher score for more shared methods
            score += shared_methods * 10

            # Bonus for name containment (e.g., SerializableCircle contains Circle)
            if base_name and derived_name:
                if base_name in derived_name:
                    score += 50

            # Penalty for large slot count differences
            slot_diff = derived_count - base_count
            score -= slot_diff * 2

            # Update best base if this is better
            if score > best_score:
                best_score = score
                best_base = base_vt

        # Accept inheritance if score is reasonable
        if best_base and best_score > 0:
            inheritance[derived_vt['ea']] = [best_base['ea']]

    return inheritance


def analyze_vtable(vt, class_name, inheritance_map, all_vtables):
    """Analyze a single vtable and return structured information."""
    result = {
        'ea': vt['ea'],
        'class_name': class_name,
        'method_count': len(vt['methods']),
        'has_rtti': vt['typeinfo_ptr'] is not None,
        'methods': [],
        'base_class': None
    }

    # Add method information
    for i, (slot_ea, func_ea) in enumerate(vt['methods']):
        func_name = get_function_name(func_ea)
        short_name = get_short_method_name(func_name, class_name)

        # Try to determine method type
        method_type = "virtual"
        if 'destructor' in func_name.lower() or '~' in func_name:
            method_type = "destructor"
        elif '__cxa_pure_virtual' in func_name or 'purecall' in func_name.lower():
            method_type = "pure_virtual"
        elif 'thunk' in func_name.lower():
            method_type = "thunk"

        result['methods'].append({
            'slot': i,
            'slot_ea': slot_ea,
            'func_ea': func_ea,
            'name': short_name,
            'full_name': func_name,
            'type': method_type
        })

    # Add inheritance information
    if vt['ea'] in inheritance_map:
        base_ea = inheritance_map[vt['ea']][0]
        for bvt in all_vtables:
            if bvt['ea'] == base_ea:
                result['base_class'] = bvt.get('class_name', f'0x{base_ea:x}')
                break

    return result


def main():
    print("=" * 70)
    print("Exercise 11: Vtable Discovery + Class Layout Approximation")
    print("=" * 70)
    print()

    # Find all vtables
    print("[1] Searching for vtables...")
    vtables = find_vtables()
    print(f"    Found {len(vtables)} potential vtable(s)")
    print()

    if not vtables:
        print("No vtables found. The binary may not contain C++ classes with virtual methods.")
        return

    # Extract class names
    print("[2] Extracting class names...")
    for vt in vtables:
        # Try RTTI first
        class_name = extract_class_name_from_rtti(vt['typeinfo_ptr'])
        if not class_name:
            # Try vtable symbol name
            class_name = extract_class_name_from_vtable_name(vt['name'])
        if not class_name:
            # Generate name based on address
            class_name = f"Class_0x{vt['ea']:x}"
        vt['class_name'] = class_name

        # Also determine if this is a thunk table
        vt['is_thunk_table'] = (vt['typeinfo_ptr'] is None and
                                any('thunk' in get_function_name(ptr).lower()
                                    for _, ptr in vt['methods']))
    print()

    # Detect inheritance
    print("[3] Detecting inheritance relationships...")
    inheritance_map = detect_inheritance(vtables)
    print()

    # Analyze and output results
    print("[4] Vtable Analysis Results")
    print("=" * 70)
    print()

    # Sort vtables by address
    vtables_sorted = sorted(vtables, key=lambda x: x['ea'])

    # Separate main vtables from thunk tables
    main_vtables = [vt for vt in vtables_sorted if not vt.get('is_thunk_table', False)]
    thunk_tables = [vt for vt in vtables_sorted if vt.get('is_thunk_table', False)]

    print("--- Main Class Vtables ---")
    print()

    for vt in main_vtables:
        class_name = vt['class_name']
        analysis = analyze_vtable(vt, class_name, inheritance_map, vtables)

        print(f"Class: {class_name}")
        print(f"  Vtable Address: 0x{analysis['ea']:x}")
        print(f"  Virtual Methods: {analysis['method_count']}")
        print(f"  Has RTTI: {analysis['has_rtti']}")

        if analysis['base_class']:
            print(f"  Base Class: {analysis['base_class']}")

        print(f"  Method Table:")
        for m in analysis['methods']:
            type_indicator = ""
            if m['type'] == 'destructor':
                type_indicator = " [dtor]"
            elif m['type'] == 'pure_virtual':
                type_indicator = " [pure]"
            print(f"    [{m['slot']:2}] 0x{m['func_ea']:x}  {m['name']}{type_indicator}")
        print()

    if thunk_tables:
        print("--- Thunk Tables (Multiple Inheritance) ---")
        print()
        for vt in thunk_tables:
            print(f"  Thunk Table at 0x{vt['ea']:x} ({len(vt['methods'])} entries)")
        print()

    # Summary statistics
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Total vtables discovered: {len(vtables)}")
    print(f"  - Main class vtables: {len(main_vtables)}")
    print(f"  - Thunk tables (MI): {len(thunk_tables)}")
    print(f"Vtables with RTTI: {sum(1 for vt in vtables if vt['typeinfo_ptr'])}")
    print(f"Total virtual method slots: {sum(len(vt['methods']) for vt in vtables)}")
    print()

    # List discovered classes
    print("Discovered Classes:")
    for vt in main_vtables:
        base_info = ""
        if vt['ea'] in inheritance_map:
            base_ea = inheritance_map[vt['ea']][0]
            for bvt in main_vtables:
                if bvt['ea'] == base_ea:
                    base_info = f" : {bvt['class_name']}"
                    break
        print(f"  {vt['class_name']}{base_info} ({len(vt['methods'])} virtual methods)")

    # Build and display inheritance tree
    print()
    print("Class Hierarchy:")

    # Find root classes (no base in inheritance_map)
    roots = [vt for vt in main_vtables if vt['ea'] not in inheritance_map]

    def print_hierarchy(vt, indent=0):
        prefix = "  " * indent + ("|- " if indent > 0 else "")
        print(f"{prefix}{vt['class_name']}")
        # Find derived classes
        for derived_vt in main_vtables:
            if derived_vt['ea'] in inheritance_map:
                if inheritance_map[derived_vt['ea']][0] == vt['ea']:
                    print_hierarchy(derived_vt, indent + 1)

    for root in roots:
        print_hierarchy(root)


# Execute main
main()

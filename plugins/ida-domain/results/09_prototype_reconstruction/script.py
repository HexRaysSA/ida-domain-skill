# Exercise 09: Reconstruct Function Prototypes from Callsites
# Infers argument count and types from call sites, usage patterns, and register usage

import ida_hexrays
import ida_typeinf
import ida_funcs
import ida_ua
import ida_idp
import ida_name
import ida_bytes
from ida_idaapi import BADADDR

# Known library function signatures for pattern matching
KNOWN_SIGNATURES = {
    'memcpy': {'args': ['void *', 'const void *', 'size_t'], 'ret': 'void *'},
    'memset': {'args': ['void *', 'int', 'size_t'], 'ret': 'void *'},
    'malloc': {'args': ['size_t'], 'ret': 'void *'},
    'free': {'args': ['void *'], 'ret': 'void'},
    'strlen': {'args': ['const char *'], 'ret': 'size_t'},
    'strcmp': {'args': ['const char *', 'const char *'], 'ret': 'int'},
    'strcpy': {'args': ['char *', 'const char *'], 'ret': 'char *'},
    'printf': {'args': ['const char *'], 'ret': 'int'},
    'puts': {'args': ['const char *'], 'ret': 'int'},
}

# x64 SysV ABI argument registers (in order)
X64_SYSV_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
X64_SYSV_ARG_REG_IDS = [4, 5, 3, 2, 8, 9]  # IDA register IDs

# Windows x64 ABI argument registers
X64_WIN_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
X64_WIN_ARG_REG_IDS = [2, 3, 8, 9]


def get_arch_info():
    """Determine architecture and calling convention."""
    is_64bit = db.bitness == 64
    file_format = db.format or ""
    # Simple heuristic: check for PE in file format
    is_windows = 'PE' in file_format.upper() if file_format else False
    return is_64bit, is_windows


class CallSiteAnalyzer:
    """Analyzes call sites to infer function prototypes."""

    def __init__(self, is_64bit, is_windows):
        self.is_64bit = is_64bit
        self.is_windows = is_windows
        if is_windows:
            self.arg_regs = X64_WIN_ARG_REGS
            self.arg_reg_ids = X64_WIN_ARG_REG_IDS
        else:
            self.arg_regs = X64_SYSV_ARG_REGS
            self.arg_reg_ids = X64_SYSV_ARG_REG_IDS

    def analyze_callsite_via_decompiler(self, caller_func, callee_ea):
        """Use decompiler to analyze call site arguments."""
        try:
            cfunc = ida_hexrays.decompile(caller_func.start_ea)
            if not cfunc:
                return None

            # Find call expressions to our target
            class CallVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, target_ea):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.target_ea = target_ea
                    self.calls = []

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call:
                        # Check if this call targets our function
                        call_target = expr.x
                        if call_target.op == ida_hexrays.cot_obj:
                            if call_target.obj_ea == self.target_ea:
                                # Extract argument info
                                args = []
                                if hasattr(expr, 'a') and expr.a:
                                    for i in range(len(expr.a)):
                                        arg_expr = expr.a[i]
                                        arg_info = self._analyze_arg(arg_expr)
                                        args.append(arg_info)
                                self.calls.append({'arg_count': len(args), 'args': args})
                    return 0

                def _analyze_arg(self, expr):
                    """Analyze an argument expression to infer type."""
                    info = {'type': 'unknown', 'size': 8}

                    if expr.type:
                        tif = expr.type
                        if tif.is_ptr():
                            info['type'] = 'pointer'
                            # Check what it points to
                            pointed = tif.get_pointed_object()
                            if pointed:
                                if pointed.is_char():
                                    info['type'] = 'string_ptr'
                                elif pointed.is_void():
                                    info['type'] = 'void_ptr'
                        elif tif.is_int() or tif.is_integral():
                            size = tif.get_size()
                            info['type'] = f'int{size*8}'
                            info['size'] = size
                        elif tif.is_bool():
                            info['type'] = 'bool'
                            info['size'] = 1

                    # Check for specific patterns
                    if expr.op == ida_hexrays.cot_ref:
                        info['is_address'] = True
                    elif expr.op == ida_hexrays.cot_num:
                        info['is_immediate'] = True
                        info['value'] = expr.n._value if hasattr(expr.n, '_value') else 0

                    return info

            visitor = CallVisitor(callee_ea)
            visitor.apply_to(cfunc.body, None)
            return visitor.calls

        except Exception as e:
            return None

    def analyze_return_usage(self, caller_func, call_ea):
        """Analyze how the return value is used."""
        try:
            cfunc = ida_hexrays.decompile(caller_func.start_ea)
            if not cfunc:
                return {'type': 'unknown'}

            return_info = {'type': 'unknown', 'evidence': []}

            class ReturnAnalyzer(ida_hexrays.ctree_visitor_t):
                def __init__(self, call_addr):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
                    self.call_addr = call_addr
                    self.found_call = False
                    self.return_usage = None

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call and expr.ea == self.call_addr:
                        self.found_call = True
                        # Check parent to see how result is used
                        parent = self.parent_expr()
                        if parent:
                            self.return_usage = self._analyze_usage(parent)
                    return 0

                def _analyze_usage(self, parent):
                    if parent.op == ida_hexrays.cot_asg:
                        return {'used_as': 'assigned'}
                    elif parent.op in (ida_hexrays.cot_eq, ida_hexrays.cot_ne,
                                       ida_hexrays.cot_slt, ida_hexrays.cot_sle,
                                       ida_hexrays.cot_sgt, ida_hexrays.cot_sge):
                        return {'used_as': 'comparison', 'suggests': 'int'}
                    elif parent.op == ida_hexrays.cot_ptr:
                        return {'used_as': 'dereferenced', 'suggests': 'pointer'}
                    elif parent.op == ida_hexrays.cot_idx:
                        return {'used_as': 'array_access', 'suggests': 'pointer'}
                    return {'used_as': 'other'}

            analyzer = ReturnAnalyzer(call_ea)
            analyzer.apply_to(cfunc.body, None)

            if analyzer.return_usage:
                return_info = analyzer.return_usage

            return return_info

        except Exception:
            return {'type': 'unknown'}


class PrototypeInferrer:
    """Infers function prototypes from collected call site information."""

    def __init__(self, analyzer):
        self.analyzer = analyzer

    def infer_prototype(self, func, call_sites_info):
        """Infer a function's prototype from call site analysis."""
        if not call_sites_info:
            return None

        # Aggregate information from all call sites
        arg_counts = []
        arg_types_by_position = {}
        return_types = []

        for site_info in call_sites_info:
            if 'arg_count' in site_info:
                arg_counts.append(site_info['arg_count'])

            if 'args' in site_info:
                for i, arg in enumerate(site_info['args']):
                    if i not in arg_types_by_position:
                        arg_types_by_position[i] = []
                    arg_types_by_position[i].append(arg.get('type', 'unknown'))

            if 'return_usage' in site_info and site_info['return_usage'].get('suggests'):
                return_types.append(site_info['return_usage']['suggests'])

        # Determine most likely argument count
        if arg_counts:
            inferred_arg_count = max(set(arg_counts), key=arg_counts.count)
        else:
            inferred_arg_count = 0

        # Determine most likely type for each argument
        inferred_args = []
        for i in range(inferred_arg_count):
            if i in arg_types_by_position:
                types = arg_types_by_position[i]
                # Prefer more specific types
                if 'string_ptr' in types:
                    inferred_args.append('const char *')
                elif 'void_ptr' in types:
                    inferred_args.append('void *')
                elif 'pointer' in types:
                    inferred_args.append('void *')
                elif any('int' in t for t in types):
                    # Get the most common int size
                    int_types = [t for t in types if 'int' in t]
                    if int_types:
                        inferred_args.append(max(set(int_types), key=int_types.count).replace('int', '__int'))
                    else:
                        inferred_args.append('__int64')
                else:
                    inferred_args.append('__int64')  # Default to 64-bit int
            else:
                inferred_args.append('__int64')

        # Determine return type
        if return_types:
            if 'pointer' in return_types:
                inferred_return = 'void *'
            elif 'int' in return_types:
                inferred_return = '__int64'
            else:
                inferred_return = '__int64'
        else:
            inferred_return = '__int64'  # Default

        confidence = self._calculate_confidence(arg_counts, arg_types_by_position)

        return {
            'arg_count': inferred_arg_count,
            'args': inferred_args,
            'return_type': inferred_return,
            'confidence': confidence
        }

    def _calculate_confidence(self, arg_counts, arg_types):
        """Calculate confidence score based on evidence count and consistency."""
        if not arg_counts:
            return 0.0

        # Base confidence from sample size
        sample_size = len(arg_counts)
        base_confidence = min(sample_size / 5.0, 1.0)  # Max out at 5 samples

        # Consistency bonus
        if len(set(arg_counts)) == 1:
            consistency_bonus = 0.2
        else:
            consistency_bonus = 0.0

        return min(base_confidence + consistency_bonus, 1.0)

    def create_tinfo(self, prototype_info):
        """Create a tinfo_t from the inferred prototype."""
        if not prototype_info:
            return None

        # Map our inferred types to C-compatible types
        type_map = {
            '__int64': 'long long',
            '__int32': 'int',
            '__int16': 'short',
            '__int8': 'char',
            'void *': 'void *',
            'const char *': 'char *',
        }

        def map_type(t):
            return type_map.get(t, t)

        ret_type = map_type(prototype_info['return_type'])
        args = [map_type(a) for a in prototype_info['args']]

        # Build function type string - try with and without calling convention
        args_str = ', '.join(args) if args else 'void'

        # Try several formats
        formats = [
            f"{ret_type} func({args_str});",
            f"{ret_type} __cdecl func({args_str});",
            f"long long func({', '.join(['long long']*prototype_info['arg_count']) if prototype_info['arg_count'] > 0 else 'void'});",
        ]

        for type_str in formats:
            tif = ida_typeinf.tinfo_t()
            result = ida_typeinf.parse_decl(tif, None, type_str, ida_typeinf.PT_SIL)
            if result:
                return tif

        return None

    def format_prototype_string(self, prototype_info, func_name):
        """Format prototype as readable string."""
        if not prototype_info:
            return "unknown"

        type_map = {
            '__int64': 'int64_t',
            '__int32': 'int32_t',
            '__int16': 'int16_t',
            '__int8': 'int8_t',
        }

        def map_type(t):
            return type_map.get(t, t)

        ret_type = map_type(prototype_info['return_type'])
        args = [map_type(a) for a in prototype_info['args']]
        args_str = ', '.join(args) if args else 'void'

        return f"{ret_type} {func_name}({args_str})"


def get_unknown_functions():
    """Find functions without type information."""
    unknown_funcs = []

    for func in db.functions:
        name = db.functions.get_name(func)

        # Skip library/thunk functions
        flags = db.functions.get_flags(func)
        if flags.value & ida_funcs.FUNC_LIB:
            continue
        if flags.value & ida_funcs.FUNC_THUNK:
            continue

        # Skip functions with external names (likely imports)
        if name.startswith('_') or name.startswith('j_'):
            continue

        # Check if function has type info
        sig = db.functions.get_signature(func)
        if not sig or sig == '':
            # Also check via tinfo
            tif = db.types.get_at(func.start_ea)
            if not tif:
                unknown_funcs.append(func)

    return unknown_funcs


def analyze_function(func, analyzer, inferrer):
    """Analyze a function and infer its prototype."""
    func_name = db.functions.get_name(func)
    func_ea = func.start_ea

    # Get all callers
    callers = db.functions.get_callers(func)

    if not callers:
        return None

    call_sites_info = []

    for caller in callers:
        # Analyze call site via decompiler
        decompiler_info = analyzer.analyze_callsite_via_decompiler(caller, func_ea)
        if decompiler_info:
            for info in decompiler_info:
                call_sites_info.append(info)

        # Also analyze return value usage
        # Find actual call instruction addresses
        for inst in db.functions.get_instructions(caller):
            if db.instructions.is_call_instruction(inst):
                for target in db.xrefs.calls_from_ea(inst.ea):
                    if target == func_ea:
                        return_usage = analyzer.analyze_return_usage(caller, inst.ea)
                        if return_usage:
                            call_sites_info.append({'return_usage': return_usage})

    # Infer prototype
    prototype = inferrer.infer_prototype(func, call_sites_info)

    return {
        'func': func,
        'name': func_name,
        'ea': func_ea,
        'caller_count': len(callers),
        'call_site_count': len(call_sites_info),
        'prototype': prototype
    }


def get_decompilation(func):
    """Get function decompilation as string."""
    try:
        lines = db.functions.get_pseudocode(func)
        return '\n'.join(lines) if lines else '[Decompilation failed]'
    except Exception as e:
        return f'[Decompilation error: {e}]'


def apply_prototype(func, tinfo):
    """Apply inferred prototype to function."""
    return db.types.apply_at(tinfo, func.start_ea)


# Main analysis
print("=" * 80)
print("Exercise 09: Reconstruct Function Prototypes from Callsites")
print("=" * 80)
print()

# Get architecture info
is_64bit, is_windows = get_arch_info()
print(f"Architecture: {'64-bit' if is_64bit else '32-bit'}")
print(f"Platform: {'Windows' if is_windows else 'Unix/Linux (SysV ABI)'}")
print()

# Initialize analyzers
analyzer = CallSiteAnalyzer(is_64bit, is_windows)
inferrer = PrototypeInferrer(analyzer)

# Find unknown functions
print("Finding functions without type information...")
unknown_funcs = get_unknown_functions()
print(f"Found {len(unknown_funcs)} functions without type info")
print()

# Sort functions by number of callers (more callers = better evidence)
funcs_with_callers = []
for func in unknown_funcs:
    callers = db.functions.get_callers(func)
    if callers:
        funcs_with_callers.append((func, len(callers)))

# Sort by caller count descending
funcs_with_callers.sort(key=lambda x: x[1], reverse=True)

print("Functions sorted by caller count:")
for func, count in funcs_with_callers[:15]:
    name = db.functions.get_name(func)
    print(f"  {name} @ 0x{func.start_ea:08X}: {count} callers")
print()

# Take top 10 by caller count for analysis
target_funcs = [f[0] for f in funcs_with_callers[:10]]

results = []
for func in target_funcs:
    result = analyze_function(func, analyzer, inferrer)
    if result and result['prototype']:
        results.append(result)

# Print results
print("=" * 80)
print("PROTOTYPE RECONSTRUCTION RESULTS")
print("=" * 80)
print()

for result in results:
    print(f"Function: {result['name']} @ 0x{result['ea']:08X}")
    print(f"  Called from {result['caller_count']} functions, {result['call_site_count']} call sites analyzed")
    print()

    if result['prototype']:
        proto = result['prototype']
        print(f"  INFERRED PROTOTYPE:")
        print(f"    Return type: {proto['return_type']}")
        print(f"    Argument count: {proto['arg_count']}")
        if proto['args']:
            print(f"    Arguments: {', '.join(proto['args'])}")
        print(f"    Confidence: {proto['confidence']:.1%}")

        # Build prototype string
        args_str = ', '.join(proto['args']) if proto['args'] else 'void'
        proto_str = f"{proto['return_type']} __fastcall {result['name']}({args_str})"
        print(f"    Prototype: {proto_str}")
        print()

        # Get before decompilation
        print("  BEFORE applying type:")
        before_decomp = get_decompilation(result['func'])
        for line in before_decomp.split('\n')[:10]:  # First 10 lines
            print(f"    {line}")
        if before_decomp.count('\n') > 10:
            print("    ...")
        print()

        # Create and apply tinfo
        tinfo = inferrer.create_tinfo(proto)
        if tinfo:
            # Store for reference (don't actually apply without --save)
            print(f"  Created tinfo_t successfully")
            print(f"  Type string: {tinfo}")
            print(f"  (Type would be applied with --save flag)")
        else:
            # Still display the inferred prototype even if tinfo creation failed
            formatted = inferrer.format_prototype_string(proto, result['name'])
            print(f"  Note: tinfo_t creation failed, but inferred prototype is:")
            print(f"    {formatted}")

    print("-" * 60)
    print()

# Summary
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print()
print(f"Total functions analyzed: {len(target_funcs)}")
print(f"Functions with inferred prototypes: {len(results)}")

if results:
    # Calculate average confidence
    avg_confidence = sum(r['prototype']['confidence'] for r in results) / len(results)
    print(f"Average confidence: {avg_confidence:.1%}")

    # Breakdown by argument count
    arg_counts = {}
    for r in results:
        count = r['prototype']['arg_count']
        arg_counts[count] = arg_counts.get(count, 0) + 1

    print()
    print("Argument count distribution:")
    for count, num in sorted(arg_counts.items()):
        print(f"  {count} args: {num} functions")

    # High confidence functions
    high_conf = [r for r in results if r['prototype']['confidence'] >= 0.6]
    print()
    print(f"High confidence (>=60%) prototypes: {len(high_conf)}")
    for r in high_conf:
        proto = r['prototype']
        args_str = ', '.join(proto['args']) if proto['args'] else 'void'
        print(f"  {proto['return_type']} {r['name']}({args_str}) [{proto['confidence']:.0%}]")

print()
print("=" * 80)
print("Analysis complete!")

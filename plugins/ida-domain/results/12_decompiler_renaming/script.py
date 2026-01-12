"""
Exercise 12: Systematically Rename Parameters/Locals in Decompiler

This script analyzes decompiled functions and renames local variables/parameters
based on their usage patterns with well-known APIs like malloc, memcpy, strlen, etc.
"""

import ida_hexrays
import ida_lines

# API signature definitions: API name -> list of (param_index, suggested_name, description)
# param_index -1 means return value
API_SIGNATURES = {
    # Memory operations
    'malloc': [(-1, 'ptr', 'allocated memory pointer'), (0, 'size', 'allocation size')],
    'calloc': [(-1, 'ptr', 'allocated memory pointer'), (0, 'nmemb', 'number of elements'), (1, 'size', 'element size')],
    'realloc': [(-1, 'new_ptr', 'reallocated pointer'), (0, 'ptr', 'original pointer'), (1, 'size', 'new size')],
    'free': [(0, 'ptr', 'pointer to free')],

    'memcpy': [(-1, 'dst', 'destination pointer'), (0, 'dst', 'destination buffer'), (1, 'src', 'source buffer'), (2, 'len', 'copy length')],
    'memmove': [(-1, 'dst', 'destination pointer'), (0, 'dst', 'destination buffer'), (1, 'src', 'source buffer'), (2, 'len', 'move length')],
    'memset': [(-1, 'dst', 'destination pointer'), (0, 'dst', 'buffer to set'), (1, 'val', 'value to set'), (2, 'len', 'length')],
    'memcmp': [(-1, 'cmp_result', 'comparison result'), (0, 'buf1', 'first buffer'), (1, 'buf2', 'second buffer'), (2, 'len', 'comparison length')],

    # String operations
    'strlen': [(-1, 'len', 'string length'), (0, 'str', 'string to measure')],
    'strcpy': [(-1, 'dst', 'destination string'), (0, 'dst', 'destination buffer'), (1, 'src', 'source string')],
    'strncpy': [(-1, 'dst', 'destination string'), (0, 'dst', 'destination buffer'), (1, 'src', 'source string'), (2, 'n', 'max chars')],
    'strcat': [(-1, 'dst', 'concatenated string'), (0, 'dst', 'destination buffer'), (1, 'src', 'string to append')],
    'strncat': [(-1, 'dst', 'concatenated string'), (0, 'dst', 'destination buffer'), (1, 'src', 'string to append'), (2, 'n', 'max chars')],
    'strcmp': [(-1, 'cmp_result', 'comparison result'), (0, 'str1', 'first string'), (1, 'str2', 'second string')],
    'strncmp': [(-1, 'cmp_result', 'comparison result'), (0, 'str1', 'first string'), (1, 'str2', 'second string'), (2, 'n', 'max chars')],
    'strchr': [(-1, 'found_ptr', 'found character pointer'), (0, 'str', 'string to search'), (1, 'ch', 'character to find')],
    'strrchr': [(-1, 'found_ptr', 'found character pointer'), (0, 'str', 'string to search'), (1, 'ch', 'character to find')],
    'strstr': [(-1, 'found_ptr', 'found substring pointer'), (0, 'haystack', 'string to search'), (1, 'needle', 'substring to find')],
    'strdup': [(-1, 'dup_str', 'duplicated string'), (0, 'str', 'string to duplicate')],
    'strtok': [(-1, 'token', 'next token'), (0, 'str', 'string to tokenize'), (1, 'delim', 'delimiter')],
    'sprintf': [(0, 'dst', 'destination buffer'), (1, 'fmt', 'format string')],
    'snprintf': [(0, 'dst', 'destination buffer'), (1, 'size', 'buffer size'), (2, 'fmt', 'format string')],

    # File I/O
    'fopen': [(-1, 'fp', 'file pointer'), (0, 'path', 'file path'), (1, 'mode', 'open mode')],
    'fclose': [(0, 'fp', 'file pointer to close')],
    'fread': [(-1, 'bytes_read', 'bytes read'), (0, 'buf', 'read buffer'), (1, 'size', 'element size'), (2, 'count', 'element count'), (3, 'fp', 'file pointer')],
    'fwrite': [(-1, 'bytes_written', 'bytes written'), (0, 'buf', 'write buffer'), (1, 'size', 'element size'), (2, 'count', 'element count'), (3, 'fp', 'file pointer')],
    'fseek': [(0, 'fp', 'file pointer'), (1, 'offset', 'seek offset'), (2, 'whence', 'seek origin')],
    'ftell': [(-1, 'pos', 'file position'), (0, 'fp', 'file pointer')],
    'fgets': [(-1, 'result', 'result string'), (0, 'buf', 'line buffer'), (1, 'size', 'buffer size'), (2, 'fp', 'file pointer')],
    'fputs': [(0, 'str', 'string to write'), (1, 'fp', 'file pointer')],
    'fgetc': [(-1, 'ch', 'character read'), (0, 'fp', 'file pointer')],
    'fputc': [(0, 'ch', 'character to write'), (1, 'fp', 'file pointer')],
    'open': [(-1, 'fd', 'file descriptor'), (0, 'path', 'file path'), (1, 'flags', 'open flags')],
    'close': [(0, 'fd', 'file descriptor')],
    'read': [(-1, 'bytes_read', 'bytes read'), (0, 'fd', 'file descriptor'), (1, 'buf', 'read buffer'), (2, 'count', 'bytes to read')],
    'write': [(-1, 'bytes_written', 'bytes written'), (0, 'fd', 'file descriptor'), (1, 'buf', 'write buffer'), (2, 'count', 'bytes to write')],
    'lseek': [(-1, 'pos', 'new position'), (0, 'fd', 'file descriptor'), (1, 'offset', 'seek offset'), (2, 'whence', 'seek origin')],

    # Network
    'socket': [(-1, 'sock', 'socket descriptor'), (0, 'domain', 'address family'), (1, 'type', 'socket type'), (2, 'protocol', 'protocol')],
    'connect': [(0, 'sock', 'socket descriptor'), (1, 'addr', 'server address'), (2, 'addrlen', 'address length')],
    'bind': [(0, 'sock', 'socket descriptor'), (1, 'addr', 'bind address'), (2, 'addrlen', 'address length')],
    'listen': [(0, 'sock', 'socket descriptor'), (1, 'backlog', 'connection backlog')],
    'accept': [(-1, 'client_sock', 'client socket'), (0, 'sock', 'listening socket'), (1, 'addr', 'client address'), (2, 'addrlen', 'address length pointer')],
    'send': [(-1, 'bytes_sent', 'bytes sent'), (0, 'sock', 'socket descriptor'), (1, 'buf', 'send buffer'), (2, 'len', 'data length'), (3, 'flags', 'send flags')],
    'recv': [(-1, 'bytes_recv', 'bytes received'), (0, 'sock', 'socket descriptor'), (1, 'buf', 'receive buffer'), (2, 'len', 'buffer length'), (3, 'flags', 'receive flags')],
    'sendto': [(-1, 'bytes_sent', 'bytes sent'), (0, 'sock', 'socket descriptor'), (1, 'buf', 'send buffer'), (2, 'len', 'data length'), (3, 'flags', 'send flags'), (4, 'dest_addr', 'destination address'), (5, 'addrlen', 'address length')],
    'recvfrom': [(-1, 'bytes_recv', 'bytes received'), (0, 'sock', 'socket descriptor'), (1, 'buf', 'receive buffer'), (2, 'len', 'buffer length'), (3, 'flags', 'receive flags'), (4, 'src_addr', 'source address'), (5, 'addrlen', 'address length pointer')],
    'gethostbyname': [(-1, 'hostent', 'host entry'), (0, 'hostname', 'hostname to resolve')],
    'inet_addr': [(-1, 'ip_addr', 'IP address'), (0, 'ip_str', 'IP string')],
    'inet_ntoa': [(-1, 'ip_str', 'IP string'), (0, 'in_addr', 'IP address structure')],
    'htons': [(-1, 'net_order', 'network byte order'), (0, 'host_val', 'host byte order value')],
    'ntohs': [(-1, 'host_order', 'host byte order'), (0, 'net_val', 'network byte order value')],
    'htonl': [(-1, 'net_order', 'network byte order'), (0, 'host_val', 'host byte order value')],
    'ntohl': [(-1, 'host_order', 'host byte order'), (0, 'net_val', 'network byte order value')],

    # Crypto (common patterns)
    'EVP_CIPHER_CTX_new': [(-1, 'cipher_ctx', 'cipher context')],
    'EVP_EncryptInit': [(0, 'ctx', 'cipher context'), (1, 'cipher', 'cipher type'), (2, 'key', 'encryption key'), (3, 'iv', 'initialization vector')],
    'EVP_EncryptUpdate': [(0, 'ctx', 'cipher context'), (1, 'out', 'ciphertext output'), (2, 'outlen', 'output length'), (3, 'in', 'plaintext input'), (4, 'inlen', 'input length')],
    'EVP_DecryptInit': [(0, 'ctx', 'cipher context'), (1, 'cipher', 'cipher type'), (2, 'key', 'decryption key'), (3, 'iv', 'initialization vector')],
    'EVP_DecryptUpdate': [(0, 'ctx', 'cipher context'), (1, 'out', 'plaintext output'), (2, 'outlen', 'output length'), (3, 'in', 'ciphertext input'), (4, 'inlen', 'input length')],
    'MD5_Init': [(0, 'md5_ctx', 'MD5 context')],
    'MD5_Update': [(0, 'md5_ctx', 'MD5 context'), (1, 'data', 'data to hash'), (2, 'len', 'data length')],
    'MD5_Final': [(0, 'digest', 'MD5 digest'), (1, 'md5_ctx', 'MD5 context')],
    'SHA1_Init': [(0, 'sha1_ctx', 'SHA1 context')],
    'SHA1_Update': [(0, 'sha1_ctx', 'SHA1 context'), (1, 'data', 'data to hash'), (2, 'len', 'data length')],
    'SHA1_Final': [(0, 'digest', 'SHA1 digest'), (1, 'sha1_ctx', 'SHA1 context')],
    'SHA256_Init': [(0, 'sha256_ctx', 'SHA256 context')],
    'SHA256_Update': [(0, 'sha256_ctx', 'SHA256 context'), (1, 'data', 'data to hash'), (2, 'len', 'data length')],
    'SHA256_Final': [(0, 'digest', 'SHA256 digest'), (1, 'sha256_ctx', 'SHA256 context')],
}


class CallArgumentVisitor(ida_hexrays.ctree_visitor_t):
    """Visitor to find API calls and their arguments in pseudocode."""

    def __init__(self, cfunc, db):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.db = db
        # Map: lvar_index -> list of (suggested_name, api_name, param_description)
        self.var_suggestions = {}
        # Track return value assignments: lvar_index -> (suggested_name, api_name, description)
        self.return_suggestions = {}

    def visit_expr(self, expr):
        """Visit expression nodes to find function calls."""
        if expr.op == ida_hexrays.cot_call:
            self._process_call(expr)
        elif expr.op == ida_hexrays.cot_asg:
            # Check for return value assignment: var = func()
            self._process_assignment(expr)
        return 0

    def _get_callee_name(self, call_expr):
        """Get the name of the called function."""
        callee = call_expr.x
        if callee.op == ida_hexrays.cot_obj:
            # Direct call to named function
            name = self.db.names.get_at(callee.obj_ea)
            return name if name else None
        elif callee.op == ida_hexrays.cot_helper:
            # Helper function (e.g., compiler intrinsics)
            return callee.helper
        return None

    def _process_call(self, call_expr):
        """Process a function call and extract argument variable mappings."""
        callee_name = self._get_callee_name(call_expr)
        if not callee_name:
            return

        # Check if we have signature info for this API
        # Try exact match first, then try common variations
        api_info = None
        for api_name in API_SIGNATURES:
            if api_name == callee_name or callee_name.startswith('_' + api_name) or callee_name.endswith(api_name):
                api_info = API_SIGNATURES[api_name]
                break

        if not api_info:
            return

        # Process each argument
        args = call_expr.a
        for param_idx, suggested_name, description in api_info:
            if param_idx < 0:
                continue  # Return value handled in _process_assignment
            if param_idx >= len(args):
                continue

            arg_expr = args[param_idx]
            lvar_idx = self._get_lvar_from_expr(arg_expr)
            if lvar_idx is not None:
                if lvar_idx not in self.var_suggestions:
                    self.var_suggestions[lvar_idx] = []
                self.var_suggestions[lvar_idx].append((suggested_name, callee_name, description))

    def _process_assignment(self, asg_expr):
        """Process assignment to check for return value of API calls."""
        lhs = asg_expr.x
        rhs = asg_expr.y

        # Check if RHS is a call
        if rhs.op != ida_hexrays.cot_call:
            return

        # Check if LHS is a variable
        lvar_idx = self._get_lvar_from_expr(lhs)
        if lvar_idx is None:
            return

        callee_name = self._get_callee_name(rhs)
        if not callee_name:
            return

        # Check if we have signature info for this API
        api_info = None
        for api_name in API_SIGNATURES:
            if api_name == callee_name or callee_name.startswith('_' + api_name) or callee_name.endswith(api_name):
                api_info = API_SIGNATURES[api_name]
                break

        if not api_info:
            return

        # Find return value suggestion (param_idx == -1)
        for param_idx, suggested_name, description in api_info:
            if param_idx == -1:
                if lvar_idx not in self.return_suggestions:
                    self.return_suggestions[lvar_idx] = (suggested_name, callee_name, description)
                break

    def _get_lvar_from_expr(self, expr):
        """Extract local variable index from an expression if it's a simple variable reference."""
        if expr.op == ida_hexrays.cot_var:
            return expr.v.idx
        # Handle cast to variable
        if expr.op == ida_hexrays.cot_cast:
            return self._get_lvar_from_expr(expr.x)
        # Handle reference to variable (&var)
        if expr.op == ida_hexrays.cot_ref:
            return self._get_lvar_from_expr(expr.x)
        return None


def rename_local_variable(cfunc, lvar_idx, new_name):
    """Rename a local variable in the decompiled function."""
    if lvar_idx >= cfunc.lvars.size():
        return False

    lvar = cfunc.lvars[lvar_idx]

    # Use ida_hexrays to rename
    # We need to use modify_user_lvar_info or lvar_t.set_lvar_name
    success = ida_hexrays.rename_lvar(cfunc.entry_ea, lvar.name, new_name)
    return success


def get_best_suggestion(suggestions_list):
    """Choose the best name suggestion from multiple suggestions."""
    if not suggestions_list:
        return None

    # Count occurrences of each suggested name
    name_counts = {}
    for suggested_name, api_name, desc in suggestions_list:
        if suggested_name not in name_counts:
            name_counts[suggested_name] = 0
        name_counts[suggested_name] += 1

    # Return the most common suggestion
    best_name = max(name_counts, key=name_counts.get)
    # Find the full info for this name
    for suggested_name, api_name, desc in suggestions_list:
        if suggested_name == best_name:
            return (suggested_name, api_name, desc)
    return None


def make_unique_name(base_name, used_names):
    """Generate a unique variable name avoiding conflicts."""
    if base_name not in used_names:
        return base_name

    counter = 2
    while f"{base_name}{counter}" in used_names:
        counter += 1
    return f"{base_name}{counter}"


def analyze_and_rename_function(db, func):
    """Analyze a single function and return renaming suggestions."""
    func_name = db.functions.get_name(func)
    func_ea = func.start_ea

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return None
    except Exception as e:
        return None

    # Visit the function body to find API calls
    visitor = CallArgumentVisitor(cfunc, db)
    visitor.apply_to(cfunc.body, None)

    # Collect all suggestions
    all_suggestions = {}

    # Merge argument suggestions
    for lvar_idx, suggestions in visitor.var_suggestions.items():
        best = get_best_suggestion(suggestions)
        if best:
            all_suggestions[lvar_idx] = best

    # Add return value suggestions (lower priority than argument patterns)
    for lvar_idx, suggestion in visitor.return_suggestions.items():
        if lvar_idx not in all_suggestions:
            all_suggestions[lvar_idx] = suggestion

    if not all_suggestions:
        return None

    # Build renaming report
    renames = []
    used_names = set()

    # Collect existing variable names
    for i in range(cfunc.lvars.size()):
        used_names.add(cfunc.lvars[i].name)

    for lvar_idx, (suggested_name, api_name, description) in all_suggestions.items():
        if lvar_idx >= cfunc.lvars.size():
            continue

        lvar = cfunc.lvars[lvar_idx]
        original_name = lvar.name

        # Skip if already has a meaningful name (not auto-generated)
        if not original_name.startswith(('v', 'a')) or len(original_name) > 4:
            # Probably already has a user-defined name
            if not any(c.isdigit() for c in original_name[1:]):
                continue

        # Generate unique name
        new_name = make_unique_name(suggested_name, used_names)
        used_names.add(new_name)

        # Attempt rename
        success = rename_local_variable(cfunc, lvar_idx, new_name)

        renames.append({
            'original': original_name,
            'new': new_name,
            'api': api_name,
            'reason': description,
            'success': success
        })

    if not renames:
        return None

    return {
        'func_name': func_name,
        'func_ea': func_ea,
        'renames': renames
    }


def main():
    """Main analysis function."""
    print("=" * 80)
    print("Exercise 12: Systematically Rename Parameters/Locals in Decompiler")
    print("=" * 80)
    print()

    # Get function count
    func_count = len(db.functions)
    print(f"Total functions in database: {func_count}")
    print()

    # Analyze all functions
    results = []
    analyzed_count = 0

    print("Analyzing functions for API usage patterns...")
    print("-" * 80)

    for func in db.functions:
        func_name = db.functions.get_name(func)

        # Skip library and thunk functions
        try:
            flags = db.functions.get_flags(func)
            from ida_domain.functions import FunctionFlags
            if FunctionFlags.LIB in flags or FunctionFlags.THUNK in flags:
                continue
        except:
            pass

        result = analyze_and_rename_function(db, func)
        analyzed_count += 1

        if result:
            results.append(result)

    print()
    print("=" * 80)
    print("RENAMING REPORT")
    print("=" * 80)
    print()

    total_renames = 0
    successful_renames = 0

    for result in results:
        print(f"\nFunction: {result['func_name']} (0x{result['func_ea']:08X})")
        print("-" * 60)

        for rename in result['renames']:
            status = "OK" if rename['success'] else "PROPOSED"
            print(f"  [{status}] {rename['original']} -> {rename['new']}")
            print(f"         Reason: {rename['reason']} (from {rename['api']})")
            total_renames += 1
            if rename['success']:
                successful_renames += 1

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Functions analyzed: {analyzed_count}")
    print(f"Functions with suggestions: {len(results)}")
    print(f"Total variable renames: {total_renames}")
    print(f"Successful renames: {successful_renames}")
    print(f"Proposed renames (need --save): {total_renames - successful_renames}")
    print()

    # Print consistent naming patterns used
    print("=" * 80)
    print("NAMING CONVENTIONS APPLIED")
    print("=" * 80)
    print("""
Memory Operations:
  - malloc return -> ptr, mem
  - memcpy dst -> dst, src -> src, len -> len
  - memset buffer -> dst

String Operations:
  - strlen input -> str, return -> len
  - strcpy dst -> dst, src -> src
  - strcmp inputs -> str1, str2

File I/O:
  - fopen return -> fp, path -> path
  - read/write buffer -> buf, count -> count
  - fd arguments -> fd

Network:
  - socket return -> sock
  - send/recv buffer -> buf, socket -> sock
  - address arguments -> addr
""")


if __name__ == "__main__":
    main()

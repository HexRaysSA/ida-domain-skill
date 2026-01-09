# Exercise 01: Auto-tag Function Roles (Bulk Classification)
# Classifies functions into buckets: crypto, compression, parsing, allocator, logging
# Uses heuristics based on:
# - Imported APIs and their semantics
# - String references and their content
# - Basic-block structure (loop density, branch patterns)
# - Constant patterns (magic numbers, S-boxes, format strings)
# - Callgraph position (leaf vs dispatcher vs wrapper)

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Category definitions with associated heuristics
CRYPTO_APIS = {
    'CryptAcquireContext', 'CryptReleaseContext', 'CryptGenKey', 'CryptDeriveKey',
    'CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'CryptCreateHash',
    'BCryptOpenAlgorithmProvider', 'BCryptEncrypt', 'BCryptDecrypt',
    'EVP_EncryptInit', 'EVP_DecryptInit', 'AES_encrypt', 'AES_decrypt',
    'MD5_Init', 'MD5_Update', 'MD5_Final', 'SHA1_Init', 'SHA256_Init',
    'RC4', 'DES_ecb_encrypt', 'RSA_public_encrypt', 'RSA_private_decrypt'
}

COMPRESSION_APIS = {
    'compress', 'uncompress', 'deflate', 'inflate', 'deflateInit', 'inflateInit',
    'deflateEnd', 'inflateEnd', 'compress2', 'compressBound',
    'LZ4_compress', 'LZ4_decompress', 'ZSTD_compress', 'ZSTD_decompress',
    'BZ2_bzCompress', 'BZ2_bzDecompress', 'lzma_code', 'lzma_stream_decoder'
}

ALLOCATOR_APIS = {
    'malloc', 'free', 'calloc', 'realloc', 'HeapAlloc', 'HeapFree',
    'VirtualAlloc', 'VirtualFree', 'LocalAlloc', 'LocalFree',
    'GlobalAlloc', 'GlobalFree', 'mmap', 'munmap', 'brk', 'sbrk',
    'operator new', 'operator delete', '_aligned_malloc', '_aligned_free'
}

LOGGING_APIS = {
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'puts', 'fputs', 'OutputDebugString', 'OutputDebugStringA', 'OutputDebugStringW',
    'syslog', 'vsyslog', 'WriteFile', 'WriteConsole', 'DbgPrint',
    'wprintf', 'fwprintf', 'swprintf', 'vswprintf'
}

PARSING_APIS = {
    'sscanf', 'fscanf', 'scanf', 'strtok', 'strtol', 'strtoul', 'atoi', 'atol',
    'strstr', 'strchr', 'strrchr', 'strpbrk', 'strsep', 'memchr',
    'json_parse', 'json_object_get', 'xml_parse', 'yaml_parse',
    'regex_match', 're_match', 'pcre_exec', 'regexec'
}

# Crypto magic numbers and S-box patterns
CRYPTO_CONSTANTS = {
    # AES S-box first row values
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    # AES round constants
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    # MD5 constants
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    # SHA-1 constants
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    # SHA-256 constants
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    # RC4 initial S-box indicator (256 sequential values)
    # CRC32 polynomial
    0xedb88320, 0x04c11db7,
    # DES constants
    0x0f0f0f0f, 0x00ff00ff
}

COMPRESSION_CONSTANTS = {
    # Zlib magic numbers
    0x78, 0x9c, 0x78, 0xda, 0x78, 0x01,
    # Gzip magic
    0x1f8b,
    # LZ4 magic
    0x184d2204,
    # Zstd magic
    0xfd2fb528,
    # Bzip2 magic
    0x425a68,  # "BZh"
}

# String patterns for categorization
CRYPTO_STRING_PATTERNS = [
    r'(?i)(encrypt|decrypt|cipher|aes|des|rsa|md5|sha[0-9]*|hmac|hash|key|iv|nonce|salt|crypt)',
    r'(?i)(pkcs|x509|certificate|signature|verify|sign|digest)',
    r'(?i)(base64|b64|encoding|decoding)',
]

COMPRESSION_STRING_PATTERNS = [
    r'(?i)(compress|decompress|deflate|inflate|zlib|gzip|lz[0-9]*|zstd|brotli|bzip)',
    r'(?i)(pack|unpack|archive|extract)',
]

PARSING_STRING_PATTERNS = [
    r'(?i)(parse|parser|token|lexer|syntax|grammar)',
    r'(?i)(field|header|record|attribute|element|tag)',
    r'(?i)(xml|json|yaml|ini|csv|config|cfg)',
    r'%[0-9]*[diouxXeEfFgGaAcspn%]',  # Format specifiers
]

ALLOCATOR_STRING_PATTERNS = [
    r'(?i)(alloc|free|heap|pool|arena|buffer|cache|memory|mem)',
    r'(?i)(out of memory|allocation failed|memory error)',
]

LOGGING_STRING_PATTERNS = [
    r'(?i)(log|debug|info|warn|error|trace|fatal)',
    r'(?i)(enter|exit|called|returned)',
    r'\[%[^\]]+\]',  # Log format like [%s] or [%d]
    r'(?i)(timestamp|time|date)',
]


@dataclass
class FunctionScores:
    """Score breakdown for a function across all categories."""
    crypto: float = 0.0
    compression: float = 0.0
    parsing: float = 0.0
    allocator: float = 0.0
    logging: float = 0.0

    # Detailed breakdowns
    api_scores: Dict[str, float] = field(default_factory=dict)
    string_scores: Dict[str, float] = field(default_factory=dict)
    cfg_scores: Dict[str, float] = field(default_factory=dict)
    constant_scores: Dict[str, float] = field(default_factory=dict)
    callgraph_scores: Dict[str, float] = field(default_factory=dict)

    def get_predicted_label(self) -> Tuple[str, float]:
        """Returns the predicted category and confidence score."""
        scores = {
            'crypto': self.crypto,
            'compression': self.compression,
            'parsing': self.parsing,
            'allocator': self.allocator,
            'logging': self.logging
        }

        max_score = max(scores.values())
        if max_score <= 0:
            return 'unknown', 0.0

        predicted = max(scores, key=scores.get)

        # Calculate confidence (normalized to 0-1 range)
        total = sum(s for s in scores.values() if s > 0)
        confidence = max_score / total if total > 0 else 0.0

        return predicted, min(confidence, 1.0)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'score_breakdown': {
                'crypto': round(self.crypto, 2),
                'compression': round(self.compression, 2),
                'parsing': round(self.parsing, 2),
                'allocator': round(self.allocator, 2),
                'logging': round(self.logging, 2)
            },
            'details': {
                'api_matches': self.api_scores,
                'string_matches': self.string_scores,
                'cfg_metrics': self.cfg_scores,
                'constant_matches': self.constant_scores,
                'callgraph_position': self.callgraph_scores
            }
        }


def get_function_strings(func) -> List[str]:
    """Get all strings referenced by a function."""
    strings = []

    try:
        # Get all xrefs from the function's address range
        for ea in range(func.start_ea, func.end_ea):
            try:
                for xref in db.xrefs.from_ea(ea):
                    # Check if target is a string
                    string_item = db.strings.get_at(xref.to_ea)
                    if string_item:
                        try:
                            content = str(string_item)
                            if content and len(content) >= 2:
                                strings.append(content)
                        except:
                            pass
            except:
                continue
    except:
        pass

    return strings


def get_function_called_names(func) -> Set[str]:
    """Get names of all functions called by this function."""
    called_names = set()

    try:
        callees = db.functions.get_callees(func)
        for callee in callees:
            name = db.functions.get_name(callee)
            if name:
                called_names.add(name)
    except:
        pass

    return called_names


def get_cfg_metrics(func) -> dict:
    """Compute control flow graph metrics."""
    metrics = {
        'block_count': 0,
        'edge_count': 0,
        'cyclomatic_complexity': 0,
        'has_loops': False,
        'branch_density': 0.0
    }

    try:
        flowchart = db.functions.get_flowchart(func)
        if flowchart and len(flowchart) > 0:
            block_count = len(flowchart)
            metrics['block_count'] = block_count

            edge_count = 0
            back_edges = 0

            for block in flowchart:
                succ_count = block.count_successors()
                edge_count += succ_count

                # Check for back edges (loops)
                try:
                    for succ in block.get_successors():
                        if succ.start_ea <= block.start_ea:
                            back_edges += 1
                except:
                    pass

            metrics['edge_count'] = edge_count
            metrics['cyclomatic_complexity'] = edge_count - block_count + 2
            metrics['has_loops'] = back_edges > 0

            # Branch density = multi-successor blocks / total blocks
            multi_branch_blocks = sum(1 for b in flowchart if b.count_successors() > 1)
            metrics['branch_density'] = multi_branch_blocks / block_count if block_count > 0 else 0
    except:
        pass

    return metrics


def check_constants_in_function(func) -> dict:
    """Check for crypto/compression constants in function."""
    found_constants = {
        'crypto': [],
        'compression': []
    }

    try:
        # Get instructions and check for immediate values
        instructions = db.functions.get_instructions(func)
        if instructions:
            for inst in instructions:
                # Check operand values
                try:
                    disasm = db.bytes.get_disassembly_at(inst.ea)
                    if disasm:
                        # Extract hex values from disassembly
                        hex_matches = re.findall(r'0x[0-9a-fA-F]+|[0-9a-fA-F]{8}h', disasm)
                        for match in hex_matches:
                            try:
                                val = int(match.replace('h', ''), 16) if match.endswith('h') else int(match, 16)
                                if val in CRYPTO_CONSTANTS:
                                    found_constants['crypto'].append(hex(val))
                                if val in COMPRESSION_CONSTANTS:
                                    found_constants['compression'].append(hex(val))
                            except:
                                pass
                except:
                    pass
    except:
        pass

    return found_constants


def get_callgraph_position(func) -> dict:
    """Determine function's position in the callgraph."""
    position = {
        'is_leaf': True,
        'is_dispatcher': False,
        'is_wrapper': False,
        'caller_count': 0,
        'callee_count': 0
    }

    try:
        callers = db.functions.get_callers(func)
        callees = db.functions.get_callees(func)

        position['caller_count'] = len(callers)
        position['callee_count'] = len(callees)
        position['is_leaf'] = len(callees) == 0

        # Dispatcher: calls many functions, few callers
        if len(callees) > 5 and len(callers) <= 2:
            position['is_dispatcher'] = True

        # Wrapper: single call, many callers, small size
        func_size = func.end_ea - func.start_ea
        if len(callees) == 1 and len(callers) > 3 and func_size < 50:
            position['is_wrapper'] = True
    except:
        pass

    return position


def score_function_apis(called_names: Set[str]) -> Dict[str, float]:
    """Score based on API usage."""
    scores = defaultdict(float)

    for name in called_names:
        # Clean up the name for matching
        clean_name = name.lower()

        # Check each category
        for api in CRYPTO_APIS:
            if api.lower() in clean_name or clean_name in api.lower():
                scores['crypto'] += 3.0

        for api in COMPRESSION_APIS:
            if api.lower() in clean_name or clean_name in api.lower():
                scores['compression'] += 3.0

        for api in ALLOCATOR_APIS:
            if api.lower() in clean_name or clean_name in api.lower():
                scores['allocator'] += 3.0

        for api in LOGGING_APIS:
            if api.lower() in clean_name or clean_name in api.lower():
                scores['logging'] += 3.0

        for api in PARSING_APIS:
            if api.lower() in clean_name or clean_name in api.lower():
                scores['parsing'] += 3.0

    return dict(scores)


def score_function_strings(strings: List[str]) -> Dict[str, float]:
    """Score based on string references."""
    scores = defaultdict(float)

    for s in strings:
        # Check crypto patterns
        for pattern in CRYPTO_STRING_PATTERNS:
            if re.search(pattern, s):
                scores['crypto'] += 2.0
                break

        # Check compression patterns
        for pattern in COMPRESSION_STRING_PATTERNS:
            if re.search(pattern, s):
                scores['compression'] += 2.0
                break

        # Check parsing patterns
        for pattern in PARSING_STRING_PATTERNS:
            if re.search(pattern, s):
                scores['parsing'] += 2.0
                break

        # Check allocator patterns
        for pattern in ALLOCATOR_STRING_PATTERNS:
            if re.search(pattern, s):
                scores['allocator'] += 2.0
                break

        # Check logging patterns
        for pattern in LOGGING_STRING_PATTERNS:
            if re.search(pattern, s):
                scores['logging'] += 2.0
                break

        # Format strings indicate logging/parsing
        format_count = len(re.findall(r'%[0-9]*[diouxXeEfFgGaAcspn%]', s))
        if format_count > 0:
            scores['logging'] += format_count * 0.5
            scores['parsing'] += format_count * 0.3

    return dict(scores)


def score_function_cfg(metrics: dict) -> Dict[str, float]:
    """Score based on CFG characteristics."""
    scores = defaultdict(float)

    cc = metrics.get('cyclomatic_complexity', 0)
    has_loops = metrics.get('has_loops', False)
    branch_density = metrics.get('branch_density', 0)

    # Crypto functions often have high complexity and tight loops
    if has_loops and cc > 10:
        scores['crypto'] += 1.5

    # Compression has many loops and moderate complexity
    if has_loops and 5 < cc < 30:
        scores['compression'] += 1.0

    # Parsing has high branch density (switch statements, etc)
    if branch_density > 0.3:
        scores['parsing'] += 1.5

    # Allocators are typically simple with few branches
    if cc <= 5 and not has_loops:
        scores['allocator'] += 0.5

    # Logging functions are typically simple
    if cc <= 10 and branch_density < 0.3:
        scores['logging'] += 0.5

    return dict(scores)


def score_function_constants(found_constants: dict) -> Dict[str, float]:
    """Score based on found constants."""
    scores = defaultdict(float)

    crypto_count = len(found_constants.get('crypto', []))
    compression_count = len(found_constants.get('compression', []))

    if crypto_count > 0:
        scores['crypto'] += crypto_count * 4.0  # High weight for crypto constants

    if compression_count > 0:
        scores['compression'] += compression_count * 3.0

    return dict(scores)


def score_function_callgraph(position: dict) -> Dict[str, float]:
    """Score based on callgraph position."""
    scores = defaultdict(float)

    # Wrappers are often allocator wrappers
    if position.get('is_wrapper'):
        scores['allocator'] += 1.0

    # Dispatchers are often parsers (command/protocol dispatchers)
    if position.get('is_dispatcher'):
        scores['parsing'] += 1.5

    # Leaf functions with many callers might be logging utilities
    if position.get('is_leaf') and position.get('caller_count', 0) > 10:
        scores['logging'] += 1.0

    return dict(scores)


def classify_function(func) -> FunctionScores:
    """Classify a single function using all heuristics."""
    scores = FunctionScores()

    # Get function attributes
    func_name = db.functions.get_name(func)
    strings = get_function_strings(func)
    called_names = get_function_called_names(func)
    cfg_metrics = get_cfg_metrics(func)
    found_constants = check_constants_in_function(func)
    callgraph_pos = get_callgraph_position(func)

    # Apply scoring
    api_scores = score_function_apis(called_names)
    string_scores = score_function_strings(strings)
    cfg_scores = score_function_cfg(cfg_metrics)
    constant_scores = score_function_constants(found_constants)
    callgraph_scores = score_function_callgraph(callgraph_pos)

    # Also check function name for hints
    if func_name:
        name_lower = func_name.lower()
        for pattern in CRYPTO_STRING_PATTERNS:
            if re.search(pattern, name_lower):
                api_scores['crypto'] = api_scores.get('crypto', 0) + 2.0
                break
        for pattern in COMPRESSION_STRING_PATTERNS:
            if re.search(pattern, name_lower):
                api_scores['compression'] = api_scores.get('compression', 0) + 2.0
                break
        for pattern in PARSING_STRING_PATTERNS:
            if re.search(pattern, name_lower):
                api_scores['parsing'] = api_scores.get('parsing', 0) + 2.0
                break
        for pattern in ALLOCATOR_STRING_PATTERNS:
            if re.search(pattern, name_lower):
                api_scores['allocator'] = api_scores.get('allocator', 0) + 2.0
                break
        for pattern in LOGGING_STRING_PATTERNS:
            if re.search(pattern, name_lower):
                api_scores['logging'] = api_scores.get('logging', 0) + 2.0
                break

    # Aggregate scores
    for category in ['crypto', 'compression', 'parsing', 'allocator', 'logging']:
        total = (
            api_scores.get(category, 0) +
            string_scores.get(category, 0) +
            cfg_scores.get(category, 0) +
            constant_scores.get(category, 0) +
            callgraph_scores.get(category, 0)
        )
        setattr(scores, category, total)

    # Store details
    scores.api_scores = api_scores
    scores.string_scores = string_scores
    scores.cfg_scores = cfg_scores
    scores.constant_scores = constant_scores
    scores.callgraph_scores = callgraph_scores

    return scores


def main():
    """Main classification routine."""
    results = {
        'module': db.module,
        'total_functions': 0,
        'classified_functions': 0,
        'category_counts': {
            'crypto': 0,
            'compression': 0,
            'parsing': 0,
            'allocator': 0,
            'logging': 0,
            'unknown': 0
        },
        'functions': []
    }

    print(f"Analyzing binary: {db.module}")
    print(f"Architecture: {db.architecture}, Bitness: {db.bitness}-bit")
    print()

    # Iterate through all functions
    func_count = 0
    for func in db.functions:
        func_count += 1
        func_name = db.functions.get_name(func)
        func_ea = func.start_ea

        # Classify the function
        scores = classify_function(func)
        label, confidence = scores.get_predicted_label()

        # Store result
        func_result = {
            'ea': f'0x{func_ea:08X}',
            'name': func_name,
            'predicted_label': label,
            'confidence': round(confidence, 2),
            **scores.to_dict()
        }
        results['functions'].append(func_result)

        # Update counts
        results['category_counts'][label] = results['category_counts'].get(label, 0) + 1
        if label != 'unknown':
            results['classified_functions'] += 1

        # Print progress every 50 functions
        if func_count % 50 == 0:
            print(f"Processed {func_count} functions...")

    results['total_functions'] = func_count

    # Print summary
    print()
    print("=" * 60)
    print("CLASSIFICATION SUMMARY")
    print("=" * 60)
    print(f"Total functions analyzed: {results['total_functions']}")
    print(f"Functions with classification: {results['classified_functions']}")
    print()
    print("Category distribution:")
    for category, count in sorted(results['category_counts'].items(), key=lambda x: -x[1]):
        pct = (count / results['total_functions'] * 100) if results['total_functions'] > 0 else 0
        print(f"  {category:15s}: {count:4d} ({pct:5.1f}%)")
    print()

    # Print top functions per category
    print("=" * 60)
    print("TOP FUNCTIONS BY CATEGORY")
    print("=" * 60)

    for category in ['crypto', 'compression', 'parsing', 'allocator', 'logging']:
        print(f"\n{category.upper()}:")
        category_funcs = [f for f in results['functions']
                         if f['predicted_label'] == category and f['confidence'] > 0.3]
        category_funcs.sort(key=lambda x: -x['confidence'])

        for func_info in category_funcs[:5]:
            print(f"  {func_info['ea']} {func_info['name'][:40]:40s} "
                  f"(confidence: {func_info['confidence']:.2f})")

    # Output full JSON
    print()
    print("=" * 60)
    print("FULL JSON REPORT")
    print("=" * 60)
    print(json.dumps(results, indent=2))

    return results


# Run the classification
if __name__ == '__main__':
    main()

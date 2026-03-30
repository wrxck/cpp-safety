#!/usr/bin/env python3
"""
Claude Code PostToolUse hook for Edit|Write.
Checks C/C++ code for memory safety and security issues:
- Raw new/delete without smart pointers
- malloc/calloc/realloc/free in C++ code
- Unsafe string functions (strcpy, strcat, sprintf, gets)
- C-style casts
- Fixed-size char buffers with user input
"""

import json
import re
import sys
from pathlib import Path


CPP_EXTENSIONS = {'.cpp', '.hpp', '.h', '.c', '.cc', '.cxx', '.hxx'}


def is_cpp_file(file_path: str) -> bool:
    """check if file is a C/C++ source file"""
    return Path(file_path).suffix.lower() in CPP_EXTENSIONS


def check_cpp_safety(content: str, file_path: str) -> list[str]:
    """check C/C++ code for safety issues"""
    issues = []
    lines = content.split('\n')
    is_cpp = Path(file_path).suffix.lower() in {'.cpp', '.hpp', '.cc', '.cxx', '.hxx'}

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # skip comments
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue

        # skip #include lines
        if stripped.startswith('#'):
            continue

        # check for raw new (not in make_unique/make_shared context)
        if re.search(r'\bnew\s+\w+', stripped):
            # check if it's wrapped in smart pointer
            if not re.search(r'(make_unique|make_shared|unique_ptr|shared_ptr|reset)\s*[<(]', stripped):
                # not a placement new or nothrow
                if not re.search(r'\bnew\s*\(', stripped):
                    issues.append(f'line {i}: raw "new" without smart pointer — prefer std::make_unique or std::make_shared')

        # check for raw delete
        if re.search(r'\bdelete\s*\[?\]?\s+\w', stripped):
            issues.append(f'line {i}: raw "delete" — prefer RAII with smart pointers')

        # check for C memory functions in C++ code
        if is_cpp:
            for func in ['malloc', 'calloc', 'realloc', 'free']:
                if re.search(rf'\b{func}\s*\(', stripped):
                    issues.append(f'line {i}: {func}() in C++ code — prefer containers or smart pointers')

        # check for unsafe string functions
        unsafe_funcs = {
            'strcpy': 'use strncpy or std::string',
            'strcat': 'use strncat or std::string',
            'sprintf': 'use snprintf or std::format',
            'gets': 'use fgets or std::getline',
            'vsprintf': 'use vsnprintf',
        }
        for func, alternative in unsafe_funcs.items():
            if re.search(rf'\b{func}\s*\(', stripped):
                issues.append(f'line {i}: {func}() is buffer-overflow prone — {alternative}')

        # check for C-style casts (but not in comments or strings)
        # pattern: (Type*) or (Type &) but not (void) function calls
        c_cast = re.search(r'\(\s*(const\s+)?(unsigned\s+)?\w+\s*[*&]\s*\)', stripped)
        if c_cast:
            # exclude common false positives like function signatures
            if not re.search(r'(static_cast|dynamic_cast|reinterpret_cast|const_cast)', stripped):
                issues.append(f'line {i}: C-style cast {c_cast.group(0)} — prefer static_cast/dynamic_cast/reinterpret_cast')

        # check for fixed-size char buffers
        buf_match = re.search(r'\bchar\s+\w+\s*\[\s*(\d+)\s*\]', stripped)
        if buf_match:
            size = int(buf_match.group(1))
            if size > 0:
                issues.append(f'line {i}: fixed-size char[{size}] buffer — consider std::string or std::array for safety')

    return issues


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = input_data.get('tool_input', {})
    file_path = tool_input.get('file_path', '')

    if not file_path or not is_cpp_file(file_path):
        sys.exit(0)

    content = tool_input.get('new_string', '') or tool_input.get('content', '')
    if not content:
        sys.exit(0)

    issues = check_cpp_safety(content, file_path)

    if issues:
        lines = [f'C/C++ safety review for {Path(file_path).name}:']
        for issue in issues[:8]:
            lines.append(f'  - {issue}')
        if len(issues) > 8:
            lines.append(f'  ... and {len(issues) - 8} more issues')
        lines.append('')
        lines.append('memory safety is critical in security-sensitive code like TrueWAF.')

        output = {
            'hookSpecificOutput': {
                'hookEventName': 'PostToolUse',
                'additionalContext': '\n'.join(lines),
            }
        }
        print(json.dumps(output))

    sys.exit(0)


if __name__ == '__main__':
    main()

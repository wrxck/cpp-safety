#!/usr/bin/env python3
"""
Claude Code PostToolUse hook for Edit|Write|MultiEdit.
Checks C/C++ code for memory safety and security issues:
- Raw new/delete without smart pointers
- malloc/calloc/realloc/free in C++ code
- Unsafe string functions (strcpy, strcat, sprintf, gets)
- C-style casts (pointer, reference, and value)
- Fixed-size char buffers with user input
"""

import json
import os
import re
import sys
from pathlib import Path


CPP_EXTENSIONS = {'.cpp', '.hpp', '.h', '.c', '.cc', '.cxx', '.hxx'}

VALUE_CAST_TYPES = (
    r'(?:u?int\w*|size_t|ssize_t|ptrdiff_t|intptr_t|uintptr_t|off_t|'
    r'double|float|char|bool|long|short|unsigned|signed|\w+_t)'
)
VALUE_CAST_RE = re.compile(
    r'\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?' + VALUE_CAST_TYPES + r'\s*\)\s*[a-zA-Z_(]'
)
POINTER_CAST_RE = re.compile(
    r'\(\s*(?:const\s+)?(?:unsigned\s+)?\w+\s*[*&]\s*\)'
)
VOID_DISCARD_RE = re.compile(r'\(\s*void\s*\)\s*\w')


def is_cpp_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CPP_EXTENSIONS


def _nearby_has_smart_pointer(lines: list[str], idx: int) -> bool:
    lo = max(0, idx - 2)
    hi = min(len(lines), idx + 3)
    window = ' '.join(lines[lo:hi])
    return bool(re.search(r'(make_unique|make_shared|unique_ptr|shared_ptr|reset)\s*[<(]', window))


def check_cpp_safety(content: str, file_path: str, label: str = '') -> list[str]:
    issues = []
    lines = content.split('\n')
    is_cpp = Path(file_path).suffix.lower() in {'.cpp', '.hpp', '.cc', '.cxx', '.hxx'}

    def prefix(i: int) -> str:
        return f'{label}line {i}' if label else f'line {i}'

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue

        if stripped.startswith('#'):
            continue

        if re.search(r'\bnew\s+\w+', stripped):
            if not re.search(r'(make_unique|make_shared|unique_ptr|shared_ptr|reset)\s*[<(]', stripped):
                if not re.search(r'\bnew\s*\(', stripped):
                    if not _nearby_has_smart_pointer(lines, i - 1):
                        issues.append(f'{prefix(i)}: raw "new" without smart pointer - prefer std::make_unique or std::make_shared')

        if re.search(r'\bdelete\s*\[?\]?\s+\w', stripped):
            issues.append(f'{prefix(i)}: raw "delete" - prefer RAII with smart pointers')

        if is_cpp:
            for func in ['malloc', 'calloc', 'realloc', 'free']:
                if re.search(rf'\b{func}\s*\(', stripped):
                    issues.append(f'{prefix(i)}: {func}() in C++ code - prefer containers or smart pointers')

        unsafe_funcs = {
            'strcpy': 'use strncpy or std::string',
            'strcat': 'use strncat or std::string',
            'sprintf': 'use snprintf or std::format',
            'gets': 'use fgets or std::getline',
            'vsprintf': 'use vsnprintf',
        }
        for func, alternative in unsafe_funcs.items():
            if re.search(rf'\b{func}\s*\(', stripped):
                issues.append(f'{prefix(i)}: {func}() is buffer-overflow prone - {alternative}')

        if not re.search(r'(static_cast|dynamic_cast|reinterpret_cast|const_cast)', stripped):
            ptr_cast = POINTER_CAST_RE.search(stripped)
            if ptr_cast:
                issues.append(f'{prefix(i)}: C-style cast {ptr_cast.group(0)} - prefer static_cast/dynamic_cast/reinterpret_cast')
            else:
                val_cast = VALUE_CAST_RE.search(stripped)
                if val_cast and not VOID_DISCARD_RE.search(stripped):
                    token = val_cast.group(0).rstrip('(').rstrip()
                    token = token[:-1] if token.endswith(tuple('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_')) else token
                    issues.append(f'{prefix(i)}: C-style value cast - prefer static_cast')

        buf_match = re.search(r'\bchar\s+\w+\s*\[\s*(\d+)\s*\]', stripped)
        if buf_match:
            size = int(buf_match.group(1))
            if size > 0:
                issues.append(f'{prefix(i)}: fixed-size char[{size}] buffer - consider std::string or std::array for safety')

    return issues


def _read_edits(tool_input: dict) -> str:
    parts = []
    new_str = tool_input.get('new_string')
    if new_str:
        parts.append(new_str)
    content = tool_input.get('content')
    if content:
        parts.append(content)
    edits = tool_input.get('edits')
    if isinstance(edits, list):
        for edit in edits:
            ns = edit.get('new_string') if isinstance(edit, dict) else None
            if ns:
                parts.append(ns)
    return '\n'.join(parts)


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = input_data.get('tool_input', {})
    file_path = tool_input.get('file_path', '')

    if not file_path or not is_cpp_file(file_path):
        sys.exit(0)

    disk_content = None
    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                disk_content = fh.read()
        except OSError:
            disk_content = None

    fragment = _read_edits(tool_input)

    if disk_content:
        issues = check_cpp_safety(disk_content, file_path)
    elif fragment:
        issues = check_cpp_safety(fragment, file_path, label='(fragment) ')
    else:
        sys.exit(0)

    if issues:
        out_lines = [f'C/C++ safety review for {Path(file_path).name}:']
        for issue in issues[:8]:
            out_lines.append(f'  - {issue}')
        if len(issues) > 8:
            out_lines.append(f'  ... and {len(issues) - 8} more issues')
        out_lines.append('')
        out_lines.append('memory safety is critical in security-sensitive code like TrueWAF.')

        output = {
            'hookSpecificOutput': {
                'hookEventName': 'PostToolUse',
                'additionalContext': '\n'.join(out_lines),
            }
        }
        print(json.dumps(output))

    sys.exit(0)


if __name__ == '__main__':
    main()

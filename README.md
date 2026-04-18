# cpp-safety

[![CI](https://github.com/wrxck/cpp-safety/actions/workflows/ci.yml/badge.svg)](https://github.com/wrxck/cpp-safety/actions/workflows/ci.yml)

C/C++ memory safety and security checks for Claude Code sessions.

## What it checks

- Raw `new`/`delete` without smart pointers -- prefer `std::make_unique`/`std::make_shared`
- `malloc`/`calloc`/`realloc`/`free` in C++ code -- prefer containers or smart pointers
- Unsafe string functions (`strcpy`, `strcat`, `sprintf`, `gets`) -- suggests safe alternatives
- C-style casts -- prefer `static_cast`/`dynamic_cast`/`reinterpret_cast`
- Fixed-size `char[]` buffers -- suggests `std::string` or `std::array`

## Installation

```
claude plugin marketplace add wrxck/claude-plugins
claude plugin install cpp-safety@wrxck-claude-plugins
```

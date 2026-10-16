# File:    vulnerable.s
# Purpose: SAST fixture (assembly). Raw syscall entry points.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: asm-syscall

.section .text
.global _start

_start:
    # CWE-242: direct execve syscall, no argument validation
    mov $59, %rax
    lea cmd(%rip), %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    syscall

legacy_entry:
    int 0x80

fast_entry:
    sysenter

.section .data
cmd:
    .asciz "/bin/sh"

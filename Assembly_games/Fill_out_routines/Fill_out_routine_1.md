section .text
global _start

_start:
    ; Step 1: Initialize registers
    mov eax, 0         ; EAX will hold the running total (initialize to 0)
    mov ecx, 5         ; ECX holds the value of N (5 in this example)
    mov ebx, 1         ; EBX will be our counter, starting at 1

sum_loop:
    ; **Student Task**: Complete the su_loop routine below.
    ; The goal is to add EBX to EAX repeatedly until EBX reaches N (ECX)
    ; Expected result: EAX should contain 15 (sum of 1+2+3+4+5)

    ; Exit program
    mov eax, 1         ; Exit syscall
    int 0x80

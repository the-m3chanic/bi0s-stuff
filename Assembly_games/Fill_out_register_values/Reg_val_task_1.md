section .text
global _start

_start:
    ; Step 1: Initialize registers with missing values
    mov eax, ???        ; Fill in this value for EAX
    mov ebx, ???        ; Fill in this value for EBX
    mov ecx, ???        ; Fill in this value for ECX
    mov edx, ???        ; Fill in this value for EDX

    ; Step 2: Perform operations
    add eax, ebx        
    sub edx, ecx        
    imul ebx, 2      
    add eax, edx    

    ; Step 3: Conditional move 
    test ecx, ecx       
    jz finalize         ; If ECX is zero, jump to finalize

    ; If ECX is not zero, we subtract 4 from EAX
    sub eax, 4

finalize:
    ; Expected register values:
    ;   EAX = 12
    ;   EBX = 6
    ;   ECX = 0
    ;   EDX = 10

    ; Exit
    mov eax, 1          ; Exit syscall
    int 0x80

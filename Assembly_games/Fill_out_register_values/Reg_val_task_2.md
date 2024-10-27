section .text
global _start

_start:
    ; Step 1: Initialize registers with missing values
    mov eax, ???         ; Fill in this value for EAX
    mov ebx, ???         ; Fill in this value for EBX
    mov ecx, ???         ; Fill in this value for ECX
    mov edx, ???         ; Fill in this value for EDX

loop_start:
    add eax, ebx
    dec ecx              
    cmp ecx, 0           
    jg loop_start        


    add edx, 2          
    sub eax, edx      

    ; Expected register values:
    ;   EAX = 20
    ;   EBX = 10
    ;   ECX = 0
    ;   EDX = 5

    ; Exit
    mov eax, 1           ; Exit syscall
    int 0x80
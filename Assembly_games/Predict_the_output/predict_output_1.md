section .text
global _start

_start:
    mov ebx, 1    
    mov ecx, 1       
    mov esi, 0       

xyz:
    mov eax, 1       
    mov edx, ecx  

abc:
    mul edx       
    dec edx          
    cmp edx, 1    
    jg abc
    add ebx, eax
    inc ecx           
    cmp ecx, 8   
    jl xyz
    mov eax, 1 
    int 0x80


What is the value inside ebx at the end of the program?
section .text
global _start

_start:
   mov ebx, [a value from input]
    ; EBX would contain the number to be checked currently 
    ; Expected output is to set eax to 0 if number is odd and eax to 1 if number is even
    ;write the code accordingly and set it to 1 or 0, and go to "finish:" for both cases
finish:
    ; Exit program
    mov eax, 1          ; Exit syscall
    int 0x80
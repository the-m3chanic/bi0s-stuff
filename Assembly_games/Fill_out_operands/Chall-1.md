; 🔢 Simple Number Fun Challenge! 🎯
; Fill in the blanks to make the program work!
; If you get it right, you'll see a success message!

section .data
    num1        dd  10          ; First number
    num2        dd  5           ; Second number
    result      dd  0           ; Where we'll store our results
    
    ; Messages to print
    success     db  "🌟 Congratulations! All operations successful! 🌟", 10, 0
    success_len equ $ - success
    
section .text
global _start

_start:
    ; Challenge 1: Add two numbers
    ; Put num1 into eax, then add num2 to it
    ???  eax, [num1]      
    ???  eax, [num2]       
    mov [result], eax
    
    ; Verify addition result (should be 15)
    ??? eax, 15
    jne exit_error
    
    ; Challenge 2: Multiply by 2
    ; Double the value in eax
    ???  eax, 1           
    mov [result], eax      ; Save result
    
    ; Verify multiplication result (should be 30)
    cmp eax, 30
    jne exit_error
    
    ; Challenge 3: Compare numbers
    mov eax, [num1]
    ???  eax, [num2]      
    jg  number_is_bigger 
    
number_is_smaller:
    mov eax, 0             ; Put 0 in eax if num1 <= num2
    jmp check_comparison

number_is_bigger:
    mov eax, 1             ; Put 1 in eax if num1 > num2

check_comparison:
    ; Verify comparison result (should be 1 since 10 > 5)
    cmp eax, 1
    jne exit_error

    ; If we got here, all operations were successful!
    ; Print success message
    mov eax, 4            ; sys_write
    mov ebx, 1            ; stdout
    mov ecx, success      ; message to write
    mov edx, success_len  ; message length
    int 0x80
    
    ; Exit successfully
    mov eax, 1            ; sys_exit
    mov ebx, 0            ; exit code 0 = success
    int 0x80

exit_error:
    ; Exit with error code
    mov eax, 1            ; sys_exit
    mov ebx, 1            ; exit code 1 = error
    int 0x80

; 🎯 Your Tasks:
;
; 1. Addition Challenge:
;    - Load num1 (10) into eax
;    - Add num2 (5) to eax
;    - Should get 15
;
; 2. Multiplication Challenge:
;    - Double the number using a single operator
;    - 15 should become 30
;
; 3. Comparison Challenge:
;    - Compare num1 (10) with num2 (5)
;    - Should set up for jump if 10 > 5
;
; Commands you can use:
; - mov  : Move value to register
; - add  : Add numbers
; - shl  : Shift left
; - cmp  : Compare numbers
;
; To compile and run:
; nasm -f elf32 program.asm -o program.o
; ld -m elf_i386 program.o -o program
; ./program
;
; If you see the success message, you got everything right!
; If the program exits without a message, check your work!
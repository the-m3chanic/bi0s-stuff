BITS 32

extern printf
extern scanf

section .data
	enter_first: db "please enter your number here: ", 25, 0
	enter_second: db "please enter your second number here: ", 25, 0
	in: db "%d", 0
	out: db "%d", 10, 0
	int1: times 4 db 0
	int2: times 4 db 0

section .text

	global main

main:
	push ebp
	mov ebp, esp

	push enter_first
	call printf
	add esp, 4

	push int1
	push in
	call scanf
	add esp, 8

	mov eax, dword [int1]


xor ebx, ebx
xor ecx, ecx
xor edx, edx
xor edi, edi
add edx, 1

fib:
	cmp ecx, eax
	je output
	inc ecx
	mov edi, edx
	add edx, ebx
	mov ebx, edi
	jmp fib

output:
	push ebx
	push out
	call printf
	add esp, 4
	jmp end

end:
	mov eax, 0
	mov esp, ebp
	pop ebp
	ret

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
	special: db "factorial of 0 is 1", 20, 0
	cheeky: db "you can't find the factorial of negative numbers :) ", 25, 0

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


xor ecx, ecx
xor ebx, ebx
add ebx, 1
add ecx, 1

cmp eax, 0
je spec
jl cheek

for:
	cmp ebx, eax
	je output
	inc ebx
	imul ecx, ebx
	jmp for


output:
	push ecx
	push out
	call printf
	add esp, 4
	jmp end


cheek:
	push cheeky
	call printf
	add esp, 4
	jmp end

spec:
	push special
	call printf
	add esp, 4
	jmp end


end:
	mov eax, 0
	mov esp, ebp
	pop ebp
	ret

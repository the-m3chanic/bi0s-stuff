BITS 32

extern printf
extern scanf

section .data
	enter_first: db "please enter your number here: ", 0
	in: db "%d", 0
	out: db "%d", 10, 0
	int1: times 4 db 0
	win_statement: db "prime!!", 10, 0
	lose_statement: db "not prime :(", 10, 0
	special_1: db "you have a special number", 10, 0
	special_2: db "prime!!", 10, 0
	special_0: db "please enter a positive number", 10, 0


section .text

	global main


main:
	xor ebx, ebx

	push ebp
	mov ebp, esp

	push enter_first
	call printf
	add esp, 8

	push int1
	push in
	call scanf
	add esp, 8

	mov ebx, dword [int1]

	xor eax, eax
	xor ecx, ecx
	xor edi, edi

	add ecx, 2
	mov edi, ebx
	sub edi, 1

	mov eax, ebx

	cmp ebx, 0
	jle spec_0

	cmp ebx, 1
	je spec_1

	cmp ebx, 2
	je spec_2

	jmp check


check:
	xor eax, eax
	add eax, ebx

	xor edx, edx

	div ecx
	cmp edx, 0
	je lose

	cmp ecx, edi
	je win

	add ecx, 1
	jmp check

win:
	push win_statement
	call printf
	add esp, 4
	jmp end


lose:
	push lose_statement
	call printf
	add esp, 4
	jmp end


spec_1:
	push special_1
	call printf
	add esp, 4
	jmp end


spec_2:
	push special_2
	call printf
	add esp, 4
	jmp end


spec_0:
	push special_0
	call printf
	add esp, 4
	jmp end


end:
	mov eax, 0
	mov esp, ebp
	pop ebp
	ret


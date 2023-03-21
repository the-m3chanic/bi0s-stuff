BITS 32

extern printf
extern scanf
global main


section .data
	enter_first: db "please enter your number here: ", 0x0
	num: times 4 dd 0x0
	in: db "%d", 0x0
	out: db "%d",0x10,0x0
	int1: times 4 dd 0x0


section .text


main:

	push ebp
	mov ebp, esp

	push enter_first
	call printf
	add esp, 0x4

	push int1
	push in
	call scanf
	add esp, 0x8

	mov eax, DWORD [int1]
	xor ebx, ebx
	mov ebx, DWORD [num]

	ror al, 4

	jmp while


while:

	inc ebx

	xor edx, edx
	xor ecx, ecx

	mov ecx, 0x2
	div ecx
	push edx
	cmp eax, 0x0
	jne while
	jmp ahout

ahout:

	dec ebx
	pop edx
	mov eax, edx

	push eax
	push out
	call printf
	add esp, 0x8

	cmp ebx, 0x0
	jne ahout
	jmp end

end:
	mov eax, 0
	mov esp, ebp
	pop ebp
	ret


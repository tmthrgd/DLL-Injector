.code

CallFunction PROC PUBLIC
	; save r15, r14 which are nonvolatile registers
	push r15
	push r14

	; save rsp into r15
	mov r15, rsp
	; save rcx into r14
	mov r14, rcx

	; align the stack to 16 bytes
	sub rsp, 8

	; move the stack arguments pointer into rax
	mov rax, QWORD PTR [r14+40]

	; is pointer 0? if so skip
	cmp rax, 0
	je SHORT $end_args

	; advance pointer length bytes
	add rax, QWORD PTR [r14+48]
$args_loop:
	; subtract 8 bytes (1 64-bit pointer)
	sub rax, 8
	; push argument at [rax] onto stack
	push QWORD PTR [rax]
	; has pointer reached the beggining
	cmp rax, QWORD PTR [r14+40]
	ja SHORT $args_loop

$end_args:
	; allocate spill space
	sub rsp, 32

	; clear rax
	xor rax, rax
	
	; mov first 4 arguments to registers
	mov rcx, QWORD PTR [r14+8]
	mov rdx, QWORD PTR [r14+16]
	mov r8, QWORD PTR [r14+24]
	mov r9, QWORD PTR [r14+32]

	; call function
	call QWORD PTR [r14]

	; move return value (rax) into structure
	mov QWORD PTR [r14+56], rax

	; restore stack pointer
	mov rsp, r15

	; restore r14, r15
	pop r14
	pop r15

	; clear return value, return ERROR_SUCCESS
	xor rax, rax

	ret 0
CallFunction ENDP

END
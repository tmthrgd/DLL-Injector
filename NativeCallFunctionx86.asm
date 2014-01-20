.model FLAT, STDCALL

.code

_TEXT SEGMENT
	; local variable __esp is at [ebp - 4]
	__esp$ = -4
	; paramater _lpThreadParameter is at [ebp + 8]
	_lpThreadParameter$ = 8

CallFunction PROC PUBLIC
	; save ebp, esi which are nonvolatile registers
	push ebp
	push esi

	; save esp into __esp local variable
	mov DWORD PTR __esp$[ebp], esp

	; mov _lpThreadParameter paramater into esi
	mov esi, DWORD PTR _lpThreadParameter$[ebp]

	; move the stack arguments pointer into eax
	mov eax, DWORD PTR [esi+40]

	; is pointer 0? if so skip
	cmp eax, 0
	je SHORT $end_args

	; advance pointer length bytes
	add eax, DWORD PTR [esi+48]
$args_loop:
	; subtract 8 bytes (1 64-bit pointer or 1 32-bit pointer with padding)
	sub eax, 8
	; push argument at [eax] onto stack
	push DWORD PTR [eax]
	; has pointer reached the beggining
	cmp eax, DWORD PTR [esi+40]
	ja SHORT $args_loop

$end_args:
	; clear eax
	xor eax, eax
	
	; (optional) move first one/two arguments into registers
	mov ecx, DWORD PTR [esi+8]
	mov edx, DWORD PTR [esi+16]

	; call function
	call DWORD PTR [esi]

	; move return value (edx:eax) into structure
	mov DWORD PTR [esi+60], edx
	mov DWORD PTR [esi+56], eax

	; restore stack pointer from __esp
	mov esp, DWORD PTR __esp$[ebp]

	; restore esi, ebp
	pop esi
	pop ebp

	; clear return value, return ERROR_SUCCESS
	xor eax, eax

	; single paramater is 32-bit pointer or 4 bytes
	ret 4
CallFunction ENDP

_TEXT ENDS

END
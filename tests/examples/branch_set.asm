global _start

section .data
byteval: db 0xFE          ; -2 in two's complement
dwordval: dd 0xFFFFFFFB   ; -5 as 32-bit

section .text
_start:
	xor rax, rax
	cmp rax, rax
	sete rax              ; set AL = 1

	movzx rbx, [byteval]
	movsx rcx, [byteval]
	movsxd rdx, [dwordval]

	cmp rax, 1
	jne fail

	cmp rbx, 0xFE
	jne fail

	cmp rcx, 0xFFFFFFFFFFFFFFFE
	jne fail

	cmp rdx, 0xFFFFFFFFFFFFFFFB
	jne fail

	mov rsi, 3
loop_again:
	dec rsi
	jnz loop_again        ; backward branch should encode short form

	mov rax, 60           ; exit
	xor rdi, rdi
	syscall

fail:
	mov rax, 60
	mov rdi, 1
	syscall

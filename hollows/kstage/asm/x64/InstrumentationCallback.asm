;;
;; KSTAGE
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

GLOBAL InstrumentationCallbackAsm
EXTERN InstrumentationCallbackEnt

[SECTION .text$C]

InstrumentationCallbackAsm:

	;;
	;; Preserve arguments
	;;
	push	rax
	push	rcx
	push	rbx
	push	rbp
	push	rdi
	push	rsi
	push	rsp
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	;;
	;; Reserve shadow space
	;;
	sub	rsp, 020h

	;;
	;; Execute callback
	;;
	call	InstrumentationCallbackEnt

	;;
	;; Restore shadow space
	;;
	add	rsp, 020h

	;;
	;; Restore arguments
	;;
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	rsp
	pop	rsi
	pop	rdi
	pop	rbp
	pop	rbx
	pop	rcx
	pop	rax
	
	;;
	;; Return
	;;
	jmp	r10


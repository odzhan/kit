;;
;; KSTAGE
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

GLOBAL Table
GLOBAL KmEvt
GLOBAL UmEvt
GLOBAL GetIp

[SECTION .text$E]

Table:
	;;
	;; Pointer to the NT Base
	;;
	dq	0

KmEvt:
	;;
	;; Event for signaling that the notify
	;; callback is no longer needed.
	;;
	dd	0

UmEvt:
	;;
	;; Event for signaling that the syscall
	;; instrumentation is no longer needed.
	;;
	dd	0

GetIp:
	;;
	;; Get current instruction addr
	;;
	call	get_ret_ptr

	;;
	;; Get address of GetIp()
	;;
	get_ret_ptr:
	pop	rax
	sub	rax, 5
	ret
Leave:
	db 'ENDOFCODE'

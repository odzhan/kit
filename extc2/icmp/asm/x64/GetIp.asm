;;
;; ICMP
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;

;;
;; Architecture
;;
[BITS 64]

;;
;; Export
;;
GLOBAL	GetIp

;;
;; Section
;;
[SECTION .text$C]

;;
;; End of code/GetIp stub
;;
GetIp:
	;;
	;; Execute next instruction
	;;
	call	get_ret_ptr

	get_ret_ptr:
	;;
	;; Pop address from return, and subtract
	;; to get the pointer to the GetIp sym.
	;;
	pop	rax
	sub	rax, 5

	;;
	;; Return
	;;
	ret

Leave:
	db 'ENDOFCODE'

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
[BITS 32]

;;
;; Export
;;
GLOBAL	_GetIp

;;
;; Section
;;
[SECTION .text$C]

;;
;; End of code/GetIp stub
;;
_GetIp:
	;;
	;; Execute next instruction
	;;
	call	_get_ret_ptr

	_get_ret_ptr:
	;;
	;; Pop address from return, and subtract
	;; to get the pointer to the GetIp sym.
	;;
	pop	eax
	sub	eax, 5

	;;
	;; Return
	;;
	ret

Leave:
	db 'ENDOFCODE'

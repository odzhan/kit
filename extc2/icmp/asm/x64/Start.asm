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
GLOBAL	Start

;;
;; Import
;;
EXTERN	Entry

;;
;; Section
;;
[SECTION .text$A]

;;
;; Start of the code
;;
Start:
	;;
	;; Setup the stack of the thread
	;;
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	;;
	;; Execute C Entrypoint
	;;
	sub	rsp, 020h
	call	Entry

	;;
	;; Cleanup the stack of the thread
	;;
	mov	rsp, rsi
	pop	rsi

	;;
	;; Return
	;;
	ret

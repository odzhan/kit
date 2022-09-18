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
GLOBAL	_Start

;;
;; Import
;;
EXTERN	_Entry

;;
;; Section
;;
[SECTION .text$A]

;;
;; Start of the code
;;
_Start:
	;;
	;; Setup the stack of the thread
	;;
	push	ebp
	mov	ebp, esp

	;;
	;; Execute C Entrypoint
	;;
	call	_Entry

	;;
	;; Cleanup the stack of the thread
	;;
	mov	esp, ebp
	pop	ebp

	;;
	;; Return
	;;
	ret

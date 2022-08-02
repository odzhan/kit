;;
;; PostEx
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

;;
;; Export
;;
GLOBAL	Payload64

[SECTION .text]

Payload64:
	incbin "payload/payload.x64.bin"

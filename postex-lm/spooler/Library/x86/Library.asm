;;
;; PostEx Lateral Movement
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;

;;
;; Include PE Library
;;
%include 'Library/include/Pe.inc'

;;
;; Create a x86 DLL
;;

DLL32

START
incbin "spooler.x86.bin"

END

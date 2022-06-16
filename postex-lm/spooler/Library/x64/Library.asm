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
;; Create a x64 DLL
;;

DLL64

START
incbin "spooler.x64.bin"

END

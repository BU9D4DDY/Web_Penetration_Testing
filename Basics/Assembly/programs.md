```assembly
;TITLE Encryption Program  (Encrypt.asm)

; This program demonstrates simple symmetric encryption using the XOR instruction.
INCLUDE Irvine32.inc
KEY = 239      ; any value between 1-255
BUFMAX = 128      ; maximum buffer size
.data
   sPrompt  BYTE  "Enter the plain text: ",0
   sEncrypt BYTE  "Cipher text:          ",0
   sDecrypt BYTE  "Decrypted:            ",0
   buffer   BYTE   BUFMAX dup(0)
   bufSize  DWORD  ?

.code
main PROC
   call InputTheString       ; input the plain text
   call TranslateBuffer      ; encrypt the buffer
   mov  edx,OFFSET sEncrypt  ; display encrypted message
   call DisplayMessage
   call TranslateBuffer      ; decrypt the buffer
   mov  edx,OFFSET sDecrypt  ; display decrypted message
   call DisplayMessage
   exit
main ENDP

InputTheString PROC
; Asks user to enter string from the keyboard. Save string and its length
; in variables. Receives: nothing. Returns: nothing
   pushad
   mov  edx,offset sPrompt    ; display a prompt
   call WriteString
   mov  ecx,BUFMAX            ; maximum character count
   mov  edx,offset buffer     ; point to the buffer
   call ReadString            ; input the string
   mov  bufSize,eax           ; save the length
   call Crlf
   popad
   ret
InputTheString ENDP

;-----------------------------------------------------
DisplayMessage PROC
;
; Display the encrypted or decrypted message.
; Receives: EDX points to the message Returns:  nothing
;-----------------------------------------------------
   pushad
   call WriteString
   mov  edx,offset buffer     ; display the buffer
   call WriteString
   call Crlf
   call Crlf
   popad
   ret
DisplayMessage ENDP

;-----------------------------------------------------
TranslateBuffer PROC
;
; Translates the string by exclusive-ORing each byte
; with the same integer.; Receives: nothing.  Returns: nothing
;-----------------------------------------------------
   pushad
   mov  ecx,bufSize     ; loop counter
   mov  esi,0           ; index 0 in buffer
L1:
   xor  buffer[esi],KEY ; translate a byte
   inc  esi             ; point to next byte
   loop L1
   popad
   ret
TranslateBuffer ENDP

END main
```


; 🚀 Space Mission: Assembly Adventures - Your Mission Control Panel! 🌟
; Fill in the missing commands to complete each mission!
; Hint: Use these commands to help: mov, add, mul, sub, and, or, cmp, jge, loop

section .data
    ; Our space equipment
    fuel        dd 100        ; Our spaceship's fuel
    score       dd 0          ; Your score
    shields     dd 0xFF       ; Shield power
    asteroids   dd 5          ; Number of asteroids
    
    ; Secret alien message to decode
    alien_msg   db "HELLO EARTHLING"
    msg_len     equ $ - alien_msg

section .bss
    decoded_msg resb 20       ; Where we'll store the decoded message

section .text
global _start

_start:
    ; ===== 🚀 Mission 1: Launch Sequence =====
    ; Mission Brief: Check if we have enough fuel to launch!
    ; We need at least 50 fuel to take off
    ; Fill in the ???
    
    ???  eax, [fuel]        
    ???  eax, 50         
    ???  launch             
    jmp mission_failed      ; Not enough fuel!

launch:
    ; ===== 🌠 Mission 2: Asteroid Points =====
    ; Mission Brief: Calculate points from collecting asteroids!
    ; Each asteroid is worth 10 points
    ; Fill in the ???
    
    ???  eax, 10           
    ???  ebx, [asteroids]  
    ???  ebx               
    ???  [score], eax      

    ; ===== 👽 Mission 3: Decode Alien Message =====
    ; Mission Brief: Decode the secret message!
    ; The message is encoded by adding 1 to each letter
    ; Fill in the ??? to decode each letter
    
    mov ecx, msg_len       ; Length of message
    mov esi, alien_msg     ; Source message
    mov edi, decoded_msg   ; Where to put decoded message

decode_loop:
    mov al, [esi]          
    ???  al, 1             
    ???  [edi], al         
    inc esi                ; Move to next letter
    inc edi
    ??? ecx
    ??? ecx, 0
    ???  decode_loop       ; HINT: Keep going until done

    ; ===== 🛡️ Mission 4: Shield Power =====
    ; Mission Brief: Power up the shields!
    ; We need to activate all shield sectors
    ; Fill in the ???
    
    ???  al, [shields]   
    ???  al, 0xFF         
    ???  [shields], al   

    ; ===== 🎯 Mission 5: Target Practice =====
    ; Mission Brief: Hit the target with exact power!
    ; Target is at position 100
    ; Fill in the ??? to check if we hit it
    
    mov eax, 100          ; Our shot position
    ???  ebx, 100        
    ???  eax, ebx         
    je hit_target         ; Success if they match!
    jmp mission_failed

hit_target:
    ; 🎉 Congratulations! All missions complete! 🎉
    mov eax, 1
    xor ebx, ebx
    int 0x80

mission_failed:
    ; 😢 Mission Failed - Try again!
    jmp _start

; ===== 📝 Your Mission Notes =====
; Commands you can use:
; mov  - Move a value
; add  - Add numbers
; sub  - Subtract numbers
; mul  - Multiply numbers
; and  - Logical AND
; or   - Logical OR
; cmp  - Compare values
; jge  - Jump if greater/equal
; je   - Jump if equal
; loop - Repeat instructions

; 🌟 Bonus Challenge! 🌟
; Try to add your own missions after completing these!
; Ideas:
; - Add a fuel consumption calculator
; - Create a space temperature converter
; - Make a star counting system
; Simple 16-bit addressing mode test
; Test with: ./rasm test16.asm -m16 -f bin -o test16.bin

section .text

start:
    ; Test 16-bit addressing modes
    mov ax, [bx]          ; [BX] = r/m=111
    mov ax, [si]          ; [SI] = r/m=100  
    mov ax, [di]          ; [DI] = r/m=101
    mov ax, [bp]          ; [BP] = r/m=110 (needs disp8)
    
    ; With displacements
    mov ax, [bx+10]       ; [BX+disp8]
    mov ax, [si+20]       ; [SI+disp8]
    mov ax, [bp+4]        ; [BP+disp8]
    
    ; Combined addressing
    mov ax, [bx+si]       ; [BX+SI] = r/m=000
    mov ax, [bx+di]       ; [BX+DI] = r/m=001
    mov ax, [bp+si]       ; [BP+SI] = r/m=010
    mov ax, [bp+di]       ; [BP+DI] = r/m=011
    
    ; With displacement
    mov ax, [bx+si+8]     ; [BX+SI+disp8]
    mov ax, [bp+di+12]    ; [BP+DI+disp8]
    
    ; 16-bit operations
    mov cx, ax
    add bx, cx
    sub dx, 5
    
    ; 8-bit operations
    mov al, 0x42
    mov bl, al
    
    ; Done
    hlt

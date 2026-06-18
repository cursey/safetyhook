bits 32

; Save context.
; Push return address (trampoline), trampoline esp, and original esp (fixed later).
push dword [trampoline]
push esp
push esp

; Push general-purpose registers.
push ebp
push eax
push ebx
push ecx
push edx
push esi
push edi
pushfd

; Reserve space for xmm0..xmm7 (128 bytes), st0..st7 (80 bytes), and mxcsr (4 bytes).
sub esp, 212

; Save xmm registers.
movdqu [esp+112], xmm7
movdqu [esp+96], xmm6
movdqu [esp+80], xmm5
movdqu [esp+64], xmm4
movdqu [esp+48], xmm3
movdqu [esp+32], xmm2
movdqu [esp+16], xmm1
movdqu [esp], xmm0

; Save x87 stack (pop from top, st0 first).
fstp tword [esp+128]
fstp tword [esp+138]
fstp tword [esp+148]
fstp tword [esp+158]
fstp tword [esp+168]
fstp tword [esp+178]
fstp tword [esp+188]
fstp tword [esp+198]

; Save MXCSR.
stmxcsr [esp+208]

; Fix stored original esp to point at the return address.
add dword [esp+244], 8

; call destination
push esp
call [destination]
add esp, 4

; Restore context.
; Restore MXCSR.
ldmxcsr [esp+208]

; Restore x87 stack (push st7 first, st0 last so st0 ends up on top).
fld tword [esp+198]
fld tword [esp+188]
fld tword [esp+178]
fld tword [esp+168]
fld tword [esp+158]
fld tword [esp+148]
fld tword [esp+138]
fld tword [esp+128]

; Restore xmm registers.
movdqu xmm0, [esp]
movdqu xmm1, [esp+16]
movdqu xmm2, [esp+32]
movdqu xmm3, [esp+48]
movdqu xmm4, [esp+64]
movdqu xmm5, [esp+80]
movdqu xmm6, [esp+96]
movdqu xmm7, [esp+112]

; Free the 212-byte save area.
add esp, 212

; Restore general-purpose registers.
popfd
pop edi
pop esi
pop edx
pop ecx
pop ebx
pop eax
pop ebp

; Skip original esp (read-only), pop trampoline esp, and return.
lea esp, [esp+4]
pop esp
ret

; Data.
destination:
dd 0

trampoline:
dd 0

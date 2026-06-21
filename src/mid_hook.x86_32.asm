bits 32

; Stack frame (Context32) at callback entry, low -> high address:
;
; +0      fpu_env                              28 (FNSAVE env part)
; +28     st[8]                                80 (FNSAVE register part, logical ST(n) order)
; +108    mxcsr                                4
; +112    xmm0 .. xmm7                         128
; +240    eflags                               4
; +244    edi, esi, edx, ecx, ebx, eax, ebp    7 * 4 = 28
; +272    original esp                         4 (Read-only -- the value pushed by push #3)
; +276    trampoline esp                       4 (The value pushed by push #2)
; +280    trampoline                           4 (Pushed by push #1)
;
; Total saved-frame size below the pushfd region = 112 (fpu+mxcsr) + 128 (xmm) = 240.

; Save context.
push dword [trampoline]
push esp ; Push trampoline esp.
push esp ; Push original esp (this gets fixed later).
push ebp
push eax
push ebx
push ecx
push edx
push esi
push edi
pushfd
sub esp, 128 ; XMM region (highest offsets in the saved frame).
movdqu [esp+112], xmm7
movdqu [esp+96], xmm6
movdqu [esp+80], xmm5
movdqu [esp+64], xmm4
movdqu [esp+48], xmm3
movdqu [esp+32], xmm2
movdqu [esp+16], xmm1
movdqu [esp], xmm0
sub esp, 112 ; FNSAVE image (108) + MXCSR (4).
fnsave [esp] ; Writes 108-byte image at [esp+0..107].
fwait
stmxcsr [esp+108] ; Save MXCSR.

; Fix stored esp: The original esp value (push #3) currently points just above the saved trampoline/trampoline_esp pair.
; Adjust by +8 so it reflects esp as it was at hook entry, before the two implicit pushes.
mov ecx, [esp+272]
add ecx, 8
mov [esp+272], ecx

; Call destination(ctx) -- ctx pointer is the current esp (== &fpu_env).
push esp
call [destination]
add esp, 4

; Restore context.
ldmxcsr [esp+108]
frstor [esp] ; Restore 108-byte FNSAVE image.
fwait
movdqu xmm0, [esp+112]
movdqu xmm1, [esp+128]
movdqu xmm2, [esp+144]
movdqu xmm3, [esp+160]
movdqu xmm4, [esp+176]
movdqu xmm5, [esp+192]
movdqu xmm6, [esp+208]
movdqu xmm7, [esp+224]
add esp, 240 ; Drop FNSAVE+MXCSR (112) and XMM (128)
popfd
pop edi
pop esi
pop edx
pop ecx
pop ebx
pop eax
pop ebp
lea esp, [esp+4] ; Skip original esp,
pop esp
ret

destination:
dd 0
trampoline:
dd 0

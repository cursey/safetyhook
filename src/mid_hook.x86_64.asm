bits 64

; save context
push qword [rel trampoline]
push rsp
push rbp
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
pushfq

; set destination parameter
lea rcx, [rsp]

; align stack, save original
mov rbx, rsp
sub rsp, 48
and rsp, -16

; call destination
call [rel destination]

; restore stack
mov rsp, rbx

; restore context
popfq
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
pop rbp
pop rsp
ret

destination:
dq 0
trampoline:
dq 0
 ; save context
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

; fix stack (store stack change in rbx)
sub rsp, 40
test rsp, 8
jz already_aligned

sub rsp, 8
mov rbx, 48
jmp finished_aligning

already_aligned:
mov rbx, 40

finished_aligning:

; call destination

call [destination]

; restore stack
add rsp, rbx

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

jmp [trampoline]

destination:
.dq 0
trampoline:
.dq 0
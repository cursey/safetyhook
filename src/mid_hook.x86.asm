; save context
push esp
push ebp
push eax
push ebx
push ecx
push edx
push esi
push edi
pushfd

; call destination
push esp
call [destination]
add esp, 4

; restore context
popfd
pop edi
pop esi
pop edx
pop ecx
pop ebx
pop eax
pop ebp
pop esp

jmp [trampoline]

destination:
.dd 0
trampoline:
.dd 0
dbg segment read write execute

include header.inc

EXTERN funcLookupFunctionByHash:proc

;dbgInitialise
;            r15 - rMM->K32
dbgInitialise proc

  push rcx
  push rdx
  push r8
  push r9
  push r10
  push r11
  push r12

  ;TODO fix issue where process doesn't attach to the parent process
  ; (when executed from CLI)

  ;attempt to call AttachConsole
  mov rdx, qword ptr[rMM+K32]
  mov rcx, 0ff394a04e19a55f9h   ;AttachConsole
  call funcLookupFunctionByHash ;
  sub rsp, 20h
  mov rcx, 0FFFFFFFEh           ;dwProcessId (DWORD)-1 for parent process
  call rax
  add rsp, 20h
  test rax, rax
  jz _GetLastError

  _GetStdHandles:

    mov rdx, qword ptr[rMM+K32]
    mov rcx, 0b38bf0fe7a967c1ah ;GetStdHandle
    call funcLookupFunctionByHash
    mov r12, rax 
    sub rsp, 20h
    mov rcx, 0FFFFFFF6h         ;STD_INPUT_HANDLE
    call r12                    ;GetStdHandle
    mov qword ptr[rMM+dbgInputHandle], rax
    mov rcx, 0FFFFFFF5h         ;STD_OUTPUT_HANDLE
    call r12                    ;GetStdHandle
    mov qword ptr[rMM+dbgOutputHandle], rax
    mov rcx, 0FFFFFFF4h         ;STD_ERROR_HANDLE
    call r12                    ;GetStdHandle
    add rsp, 20h
    mov qword ptr[rMM+dbgErrorHandle], rax

    jmp _Pops

  _GetLastError:
    mov rdx, qword ptr[rMM+K32]
    mov rcx, 0b38c1a1383363c81h   ;GetLastError
    call funcLookupFunctionByHash ;
    sub rsp, 20h
    call rax
    add rsp, 20h

    cmp rax, 05h                ;ERROR_ACCESS_DENIED
  je _GetStdHandles
    cmp rax, 06h                ;ERROR_INVALID_HANDLE
    je _AllocConsole
    cmp rax, 57h                ;ERROR_INVALID_PARAMETER
  jne _Failure

    _AllocConsole:
      mov rdx, qword ptr[rMM+K32]
      mov rcx, 0b23c62226c15a65fh;AllocConsole
      call funcLookupFunctionByHash
      sub rsp, 20h
      call rax
      add rsp, 20h
      test rax, rax
    jnz _GetStdHandles 

  _Failure:
    xor rax, rax
  _Pops:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    ret

dbgInitialise endp

dbgPrintRegister proc


dbgPrintRegister endp

END

mpep segment read execute

EXTERN funcCallFunctionByHash:proc

main proc

  ;align stack
  and rsp, 0FFFFFFFFFFFFFFF0h

  ;code to get the base address of ntdll.dll
  mov r8, qword ptr gs:[60h]    ;PEB
  mov r8, qword ptr[r8+18h]     ;PEB->Ldr (_PEB_LDR_DATA)
  lea r8, qword ptr[r8+10h]     ;_PEB_LDR_DATA->InLoadOrderModuleList (LDR_DATA_TABLE_ENTRY)
  mov r8, qword ptr[r8]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
  mov r9, qword ptr[r8]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
  mov r8, qword ptr[r9]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
    
  ;save the base address (kernel32)
  mov r15, [r8+30h]

  ;GetCurrentProcessorNumber
  mov r10, 11046ac467aef24fh     ;qwHash
  mov r11, r15
  call funcCallFunctionByHash   ;	
  mov rdx, rax                  ; ProcessorNumber
  and rdx, 00000111b
  shl rdx, 08h
  mov r14, rdx
  ;dwSize - (ProcessorNumber & 00000111b) << 08 

  ;VirtualAlloc
  mov r10, 0be0d6d6a19fbbf49h		;utilHash(VirtualAlloc)
  mov r11, r15
  xor rcx, rcx                  ;lpAddress - NULL
  mov r8, 3000h                 ;flAllocationTYpe - MEM_COMMIT | MEM_RESERVE - 3000h
  mov r9, 40h                   ;flProtect - PAGE_EXECUTE_READWRITE - 40h
  call funcCallFunctionByHash		;
  nop

  ;ExitProcess
  mov r10, 0bf82c4b790c612ceh		;utilHash(ExitProcess)
  mov r11, r15
  mov rcx, r14                  ;uExitCode
  call funcCallFunctionByHash		;
  nop

main endp

END

mpep segment read write execute

include header.inc

EXTERN funcLookupFunctionByHash:proc
EXTERN utilRand:proc

EXTERN utilEncode:proc

EXTERN dbgInitialise:proc

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
  mov rdx, r15                  ;ImageBaseAddress
  mov rcx, 11046ac467aef24fh    ;qwHash
  call funcLookupFunctionByHash ;
  call rax                      ;GetCurrentProcessorNumber

  ;dwSize - (ProcessorNumber & 00000111b) << 08 
  mov rdx, rax                  ;ProcessorNumber
  and rdx, 00000111b            ;MAX(7)
  shl rdx, 08h                  ;7h => 700h
  mov r14, rdx                  ;dwSize

  ;VirtualAlloc
  mov rdx, r15                  ;ImageBaseAddress
  mov rcx, 0be0d6d6a19fbbf49h   ;qwHash
  call funcLookupFunctionByHash ;VirtualAlloc
  mov r9, 40h                   ;flProtect - PAGE_EXECUTE_READWRITE - 40h
  mov r8, 3000h                 ;flAllocationTYpe - MEM_COMMIT | MEM_RESERVE - 3000h
  mov rdx, r14                  ;dwSize
  xor rcx, rcx                  ;lpAddress - NULL
  call rax                      ;VirtualAlloc
  test rax, rax
  jz _ExitProcess

  ;update MainMemory->genKernel32Base
  mov qword ptr[rax+genKernel32Base], r15
  mov r15, rax

  call dbgInitialise
  nop

  ;WriteConsoleA
  mov rdx, qword ptr[mainMemoryBase+genKernel32Base]
  mov rcx, 85caeb217199930eh    ;qwHash
  call funcLookupFunctionByHash ;
  sub rsp, 30h
  mov qword ptr[rsp+20h], 00h   ;lpReserved
  xor r9, r9                    ;lpNumberOfCharsWritten
  mov r8, 26                    ;nNumberOfCharsToWrite
  lea rdx, some_string          ;lpBuffer
  mov rcx, qword ptr[mainMemoryBase+dbgOutputHandle]
  call rax                      ;WriteConsoleA
  add rsp, 30h

  ;encode "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lea rcx, some_string
  mov rdx, 26
  mov r8, 0ff73d309bc332201h
  call utilEncode

  ;WriteConsoleA
  mov rdx, qword ptr[mainMemoryBase+genKernel32Base]
  mov rcx, 85caeb217199930eh    ;qwHash
  call funcLookupFunctionByHash ;
  sub rsp, 30h
  mov qword ptr[rsp+20h], 00h   ;lpReserved
  xor r9, r9                    ;lpNumberOfCharsWritten
  mov r8, 28                    ;nNumberOfCharsToWrite
  lea rdx, some_string_nl       ;lpBuffer
  mov rcx, qword ptr[mainMemoryBase+dbgOutputHandle]
  call rax                      ;WriteConsoleA
  add rsp, 30h


  ;test is_jmp
  lea rcx, _opcode_0
  call is_jmp
  nop 

  lea rcx, _opcode_1
  call is_jmp
  nop 

  lea rcx, _opcode_2
  call is_jmp
  nop 

  lea rcx, _opcode_3
  call is_jmp
  nop 

  lea rcx, _opcode_4
  call is_jmp
  nop 

  _opcode_0:
    jmp _ExitProcess
  _opcode_1:
    je  _ExitProcess
  _opcode_2:
    nop
  _opcode_3:
    allbits db 0FFh
  _opcode_4:
    jbe _ExitProcess


  _ExitProcess:
    mov r8, qword ptr gs:[60h]    ;PEB
    mov r8, qword ptr[r8+18h]     ;PEB->Ldr (_PEB_LDR_DATA)
    lea r8, qword ptr[r8+10h]     ;_PEB_LDR_DATA->InLoadOrderModuleList (LDR_DATA_TABLE_ENTRY)
    mov r8, qword ptr[r8]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
    mov r9, qword ptr[r8]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
    mov r8, qword ptr[r9]         ;_LIST_ENTRY->Flink (_LIST_ENTRY)
    mov rdx, qword ptr[r8+30h]    ;kernel32Base
    mov rcx, 0bf82c4b790c612ceh
    call funcLookupFunctionByHash
    mov rcx, r14
    call rax

  some_string_nl db 0Dh, 0Ah
  some_string db "ABCDEFGHIJKLMNOPQRSTUVWXYZ",0

main endp

END

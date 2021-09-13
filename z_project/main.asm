mpep segment read write execute

include header.inc

EXTERN funcLookupFunctionByHash:proc
EXTERN utilRand:proc

EXTERN utilEncode:proc
EXTERN utilDecode:proc

EXTERN utilEncode_full:proc
EXTERN utilDecode_full:proc

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

  ;update rMM->K32
  mov qword ptr[rax+K32], rMM
  mov rMM, rax

  ;LoadLibraryA
  mov rdx, qword ptr[rMM+K32]
  mov rcx, 0b9a3b50901ed9addh   ;qwHash
  call funcLookupFunctionByHash ;
  sub rsp, 20h
  lea rcx, WININET_DLL          ;lpLibFileName
  call rax                      ;LoadLibraryA
  add rsp, 20h
  test rax, rax
  jz _ExitProcess
  
  ;update rMM->WININET
  mov qword ptr[rMM+WININET], rax

  call dbgInitialise
  nop

  ;WriteConsoleA
  mov rdx, qword ptr[rMM+K32]
  mov rcx, 85caeb217199930eh    ;qwHash
  call funcLookupFunctionByHash ;
  sub rsp, 30h
  mov qword ptr[rsp+20h], 00h   ;lpReserved
  xor r9, r9                    ;lpNumberOfCharsWritten
  mov r8, 26                    ;nNumberOfCharsToWrite
  lea rdx, some_string          ;lpBuffer
  mov rcx, qword ptr[rMM+K32]
  call rax                      ;WriteConsoleA
  add rsp, 30h

  ;encode "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lea rcx, some_string
  mov rdx, 26
  mov r8, 0ff73d309bc332201h
  call utilEncode

  ;WriteConsoleA
  mov rdx, qword ptr[rMM+K32]
  mov rcx, 85caeb217199930eh    ;qwHash
  call funcLookupFunctionByHash ;
  sub rsp, 30h
  mov qword ptr[rsp+20h], 00h   ;lpReserved
  xor r9, r9                    ;lpNumberOfCharsWritten
  mov r8, 28                    ;nNumberOfCharsToWrite
  lea rdx, some_string_nl       ;lpBuffer
  mov rcx, qword ptr[rMM+dbgOutputHandle]
  call rax                      ;WriteConsoleA
  add rsp, 30h

  call mainBijection

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
  WININET_DLL db "wininet.dll",0

main endp

;mainBijection
mainBijection proc

  ; add pushes


  ; starting qwSeed
  mov r8, 0ff73d309bc332201h

  _Start:

	; increments qwSeed
	inc r8

    ; initialises lpBuffer to contain 00 -> FF
    xor rax, rax
    lea rcx, lpBuffer0
	lea rbx, lpChecks0
    _SetupBuffer:
      mov byte ptr[rcx+rax], al
      inc rax
      cmp rax, 100h
    jne _SetupBuffer

	; initialised lpChecks to contain 00
	xor rax, rax
	_SetupChecksBuffer:
	  mov byte ptr[rbx+rax], 00h
      inc rax
      cmp rax, 100h
    jne _SetupChecksBuffer

    ; encode lpBuffer
    lea rcx, lpBuffer0
    mov rdx, 256
    call utilEncode_full

    ; check for duplicates
	xor rax, rax
	_CheckBuffer:
      movzx rdx, byte ptr[rcx+rax]
	  cmp byte ptr[rbx+rdx], 00h
	  jne _Start
	  inc byte ptr[rbx+rdx]
	  inc rax
      cmp rax, 100h
	jne _CheckBuffer

    ; found a suitable hash (r8)


  nop

  jmp _Start

  ret

  lpBuffer0 db 256 DUP (?)

  lpChecks0 db 256 DUP (0)

mainBijection endp

;mainDownloadFile
mainDownloadFile proc


mainDownloadFile endp

END

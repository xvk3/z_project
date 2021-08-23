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

  ;VirtualAlloc
  mov r10, 0be0d6d6a19fbbf49h		;qwHash
  mov r11, r15
  xor r12, r12                  ;(is LoadLibrary needed?)
  xor r13, r13                  ;(needs clearing)
  xor rcx, rcx                  ;lpAddress - NULL
  mov rdx, 1000h                ;dwSize - 1000h (4096 bytes)
  mov r8, 3000h                 ;flAllocationTYpe - MEM_COMMIT | MEM_RESERVE - 3000h
  mov r9, 40h                   ;flProtect - PAGE_EXECUTE_READWRITE - 40h
  call funcCallFunctionByHash		;
  nop

  ; *a forwarded function
  ;GetCurrentProcessorNumber
  mov r10, 11046ac467aef24fh     ;qwHash
  mov r11, r15
  call funcCallFunctionByHash   ;
  nop
	
  ;ExitProcess
  mov r10, 0bf82c4b790c612ceh		;qwHash
  mov r11, r15
  mov rcx, rax              ;uExitCode
  call funcCallFunctionByHash		;
  nop

main endp

utilHash proc
	;rcx - null terminated string
	push rcx
	push rdx

	mov rax, 5381d
	hl:
		mov rdx, rax
		shl rax, 5
		add rax, rdx
		xor al, [rcx]
		inc rcx
	cmp byte ptr[rcx], 00h
	jne short hl		 

	pop rdx
	pop rcx
	ret

utilHash endp

END

func segment read execute

;funcCallFunctionByHash    - calls function by passed hash
;            r10 - qwHash
;            r11 - qwImageBaseAddress / lpDllName
;          returns - function return value
;          remarks - 20h of shadow space is handled
funcCallFunctionByHash proc

  ;save function parameters
  push rcx
  push rdx
  push r8
  push r9
  
  push r12                        ;used for in _CallLoadLibrary for storing the length of the dll
  push r13                        ;LoadLibraryFlag - control flog flag
  push r14                        ;VirtualSize
  push r15                        ;VirtualAddress
  push rbp                        

  xor r13, r13

  _ParseDllHeader:
  mov eax, dword ptr [r11+3ch]	  ;IMAGE_DOS_HEADER->e_lfanew
  lea rax, qword ptr [r11+rax+88h];ImageBaseAddress + e_lfanew + 88h
                                  ;88h = IMAGE_NT_HEADERS64 (size is 18h) 
                                  ;IMAGE_OPTIONAL_HEADER (size is 70h - including IMAGE_DATA_DIRECTORY[16])
  mov r14d, dword ptr[rax+04h]    ;IMAGE_DATA_DIRECTORY[0]->Size
  mov eax, dword ptr[rax]         ;IMAGE_DATA_DIRECTORY[0]->VirtualAddress
  mov r15d, eax                   ;save VirtualAddress for forwarded function testing
  add rax, r11                    ;ImageBaseAddress + IMAGE_DATA_DIRECTORY[0]->VirtualAddress

  mov ecx, dword ptr[rax+18h]     ;IMAGE_EXPORT_DIRECTORY->NumberOfNames
  mov r8d, dword ptr[rax+20h]     ;IMAGE_EXPORT_DIRECTORY->AddressOfNames
  add r8, r11                     ;ImageBaseAddress + AddressOfNames
  
  _ForEachName:  
    dec ecx
    jz _Failed                    ;could not find function in exports
                                  ;AddressOfNames is a RVA to the list of exported names
                                  ;it points to an array of NumberOfNames 32-bit values
                                  ;each being a RVA to the exported symbol name.
    lea r9, [r8+04*rcx]           ;AddressOfNames[NumberOfNames*04h]
    mov r9d, dword ptr[r9]        ;follow pointer to get second RVA
    add r9, r11                   ;ImageBaseAddress + AddressOfNames (second RVA)
    ;r9 now points to function name

    mov edx, 1505h
    _HashLoop:
      mov rbx, rdx
      shl rdx, 05h
      add rdx, rbx
      xor dl, byte ptr[r9]
      inc r9
      cmp byte ptr[r9], 00h
    jne _HashLoop
    cmp rdx, r10
  jne _ForEachName

  xor rbx, rbx
  mov r8d, dword ptr[rax+24h]     ;IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
  add r8, r11                     ;ImageBaseAddress + AddressOfNameOrdinals
  mov bx, word ptr[r8+rcx*02h]    ;AddressOfNameOrdinals[AddressOfNamesIndex[rcx]*02]

  mov r8d, dword ptr[rax+1ch]     ;IMAGE_EXPORT_DIRECTORY->AddressOfFunctions
  add r8, r11                     ;ImageBaseAddress + AddressOfFunctions
  mov eax, dword ptr[r8+rbx*04h]  ;AddressOfFunctions[FunctionOrdinal*04h]
  
  ;check if forwarded
  ;(r8d > IMAGE_DATA_DIRECTORY[0]->VirtualAddress AND r8d < VirtualAddress + Size)
  cmp rax, r15
  jb _NotForwarded
  add r14, r15
  cmp rax, r14
  jb _Forwarded
    
  _NotForwarded:
    add rax, r11                  ;ImageBaseAddress + AddressOfFunctions[FunctionOrdinal*04h]
    test r13, r13                 ;check for the LoadLibraryFlag
  jnz _CallLoadLibrary

	;pop registers used by function (for variables on the stack)
  pop rbp                       
  pop r15
  pop r14
	pop r13
	pop r12

	;pop parameters into registers for looked up function
  pop r9
  pop r8
  pop rdx
  pop rcx

  sub rsp, 20h
  call rax
  add rsp, 20h
  ret

  _Forwarded:
    add rax, r11                  ;ImageBaseAddress + AddressOfFunctions[FunctionOrdinal*04h]
    mov rsi, rax                  ;rsi is used ScanFor2E
    _LookupLoadLibrary:
      ;TODO: check if requested dll is already present in _PED_LDR_DATA (need to write a UNICODE_STRING hasher)
      mov r9, qword ptr gs:[60h]  ;PEB
      mov r9, qword ptr[r9+18h]   ;PEB->Ldr (_PEB_LDR_DATA)
      lea r9, qword ptr[r9+10h]   ;_PEB_LDR_DATA->InLoadOrderModuleList (LDR_DATA_TABLE_ENTRY)
      mov r9, qword ptr[r9]       ;_LIST_ENTRY->Flink (_LIST_ENTRY)
      mov r9, qword ptr[r9]       ;_LIST_ENTRY->Flink (_LIST_ENTRY)
      mov r9, qword ptr[r9]       ;_LIST_ENTRY->Flink (_LIST_ENTRY)
    
      ;save the base address (kernel32)
      mov r11, [r9+30h]

      ;qwLoadLibraryHash
      mov r13, 00b9a3b50901ed9addh;set qwHash / LoadLibraryFlag
      mov r10, r13                ;i was xchg'ing it before (any reason to save the origin hash??)
      jmp _ParseDllHeader

  _CallLoadLibrary:
    ;if CallLoadLibrary is jumped to it means that a forwarded function was discovered and the code has ALREADY
    ;  1. looked up the address of LoadLibrary - which is now in rax
    ;  2. initialised rsi to point to the forwarder string
    xor rcx, rcx
    _ScanFor2E:
      cmp byte ptr[rsi+rcx], 2Eh
      lea rcx, qword ptr[rcx+01h] ;lea does not effect flags, putting the increment here means
    jne _ScanFor2E                ;[rsi+rcx] points to "2Eh"

    mov r12, rcx
    add r12, 0Ch                  ;0Ch = 04h ("dll\0") + 07h
    and r12, 0fffffff8h           ;rounding to multiple of 08h
    sub rsp, r12                  ;reserve stack space for dll name
    mov rdi, rsp
    
    push rax
    _CopyForwarderStringToStack:
      lodsb
      stosb
    loop _CopyForwarderStringToStack
    pop rax

    ;write "dll\0"
    mov dword ptr[rdi], 006c6c64h

    ;hash from rsi to /0 (function name)
    mov edx, 1505h
    _HashLoop2:
      mov rbx, rdx
      shl rdx, 05h
      add rdx, rbx
      xor dl, byte ptr[rsi]
      inc rsi
      cmp byte ptr[rsi], 00h
    jne _HashLoop2
    mov r13, rdx

    ;current situation:
    ;r11 is kernel32.dll ImageBaseAddress
    ;r12 is the size of stack space reserved by dll name
    ;r13 is the hash of the forwarded function

	  ;call LoadLibraryA 
    mov rcx, rsp	                ;lpLibFileName
    sub rsp, 20h                  ;reserve shadow space for four registers (20h = 08h * 04h)
    call rax                      ;LoadLibraryA
    add rsp, 20h                  ;restore stack
    add rsp, r12                  ;remove lpLibFileName / dll name from stack

	  ;prepare registers
    mov r11, rax                  ;rax is the return value of LoadLibrary -> ImageBaseAddress
    mov r10, r13                  ;LookupLoadLibrary exchanges r10 and r13, put the original qwHash back into r10
    xor r13, r13                  ;clear qwLoadLibraryFlag so we don't attempt to call LoadLibrary again
  jmp _ParseDllHeader

  _Failed:
    pop rbp                       ;pop registers used by function
    pop r15
    pop r14
	  pop r13
	  pop r12

    pop r9                        ;pop parameters to looked up function
    pop r8
    pop rdx
    pop rcx
    ret
funcCallFunctionByHash endp

;funcCallSectionPackage
;            r10 - dwSectionName (probably should hash this)
funcCallSectionPackage proc

  push rbx
  mov rdx, qword ptr gs:[50h]     ;PEB
  mov rax, qword ptr[rdx+10h]     ;PEB->ImageBaseAddress
  mov rcx, rax

  ;analyse PE sections
  xor r9, r9
  mov r8d, dword ptr[rax+3ch]     ;IMAGE_DOS_HEADER->e_lfanew
  add r8, rax                     ;IMAGE_DOS_HEADER->e_lfanew + ImageBaseAddress
  mov bx, word ptr[r8+06h]        ;IMAGE_NT_HEADER->IMAGE_FILE_HEADER->NumberOfSections
  mov r9w, word ptr[r8+14h]       ;IMAGE_NT_HEADER->IMAGE_FILE_HEADER->SizeOfOptionalHeader
  lea rax, [r8+r9+18h]            ;IMAGE_NT_HEADER + SizeOfOptionalHeader + sizeof(IMAGE_NT_HEADER)  
  ;rax = IMAGE_SECTION_HEADER

  inc bx                          ;clear counter (for number of sections)
  xor rdx, rdx                    ;offset accumulator
  mov r9, rax

  _ForEachSection:
    lea rax, [r9+rdx]  
    dec bx
  je _Failure

    mov r8d, dword ptr[rax]       ;IMAGE_SECTION_HEADER->Name[4]
    add rdx, 28h                  ;sizeof(IMAGE_SECTION_HEADER) ???
    cmp r8d, r10d
  jne _ForEachSection

  mov r8, rcx
  ;mov ecx, dword ptr[rax+08h]     ;IMAGE_SECTION_HEADER->Misc.VirtualSize
  mov eax, dword ptr[rax+0Ch]     ;IMAGE_SECTION_HEADER->VirtualAddress
  add rax, r8                     ;add ImageBaseAddress
  pop rbx
  call rax
  ret

funcCallSectionPackage endp

END

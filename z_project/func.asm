func segment read execute

;funcCallFunctionByHash		- calls function by passed hash
;						r10 - qwHash
;						r11 - qwImageBaseAddress / lpDllName
;						r12	- qwLookupMode
;						r13 - needs to be 0
;					returns - function return value
funcCallFunctionByHash proc

	;save function parameters
	push rcx
	push rdx
	push r8
	push r9
	
	push r14
	push r15
	push rbp

	xor r13, r13

	_ParseDllHeader:
	mov eax, dword ptr [r11+3ch]	;IMAGE_DOS_HEADER->e_lfanew
	lea rax, qword ptr [r11+rax+88h];ImageBaseAddress + e_lfanew + 88h
									;88h = IMAGE_NT_HEADERS64 (size is 18h) 
									;IMAGE_OPTIONAL_HEADER (size is 70h - including IMAGE_DATA_DIRECTORY[16])
	mov r14d, dword ptr[rax+04h]	;IMAGE_DATA_DIRECTORY[0]->Size
	mov eax, dword ptr[rax]			;IMAGE_DATA_DIRECTORY[0]->VirtualAddress
	mov r15d, eax					;save VirtualAddress for forwarded function testing
	add rax, r11					;ImageBaseAddress + IMAGE_DATA_DIRECTORY[0]->VirtualAddress

	mov ecx, dword ptr[rax+18h]		;IMAGE_EXPORT_DIRECTORY->NumberOfNames
	mov r8d, dword ptr[rax+20h]		;IMAGE_EXPORT_DIRECTORY->AddressOfNames
	add r8, r11						;ImageBaseAddress + AddressOfNames
	
	_ForEachName:
		
		dec ecx
		jz _Failed					;could not find function in exports
									;AddressOfNames is a RVA to the list of exported names
									;it points to an array of NumberOfNames 32-bit values
									;each being a RVA to the exported symbol name.
		lea r9, [r8+04*rcx]			;AddressOfNames[NumberOfNames*04h]
		mov r9d, dword ptr[r9]		;follow pointer to get second RVA
		add r9, r11					;ImageBaseAddress + AddressOfNames (second RVA)
		;r9 now point to function name

		mov rdx, 5381d				;could use edx here if it is shorter
		_HashLoop:
			mov rbx, rdx
			shl rdx, 5
			add rdx, rbx
			xor dl, byte ptr[r9]	;xor with each character
			inc r9
			cmp byte ptr[r9], 00h	;check for null termination
		jne _HashLoop
		cmp rdx, r10
	jne _ForEachName

	xor rbx, rbx
	mov r8d, dword ptr[rax+24h]		;IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
	add r8, r11						;ImageBaseAddress + AddressOfNameOrdinals
	mov bx, word ptr[r8+rcx*02h]	;AddressOfNameOrdinals[AddressOfNamesIndex[rcx]*02]

	mov r8d, dword ptr[rax+1ch]		;IMAGE_EXPORT_DIRECTORY->AddressOfFunctions
	add r8, r11						;ImageBaseAddress + AddressOfFunctions
	mov eax, dword ptr[r8+rbx*04h]	;AddressOfFunctions[FunctionOrdinal*04h]
	
	;check if forwarded
	;(r8d > IMAGE_DATA_DIRECTORY[0]->VirtualAddress AND r8d < VirtualAddress + Size)
	cmp rax, r15
	jb _NotForwarded
	add r14, r15
	cmp rax, r14
	jb _Forwarded
		
	_NotForwarded:
		add rax, r11					;ImageBaseAddress + AddressOfFunctions[FunctionOrdinal*04h]
		cmp r13, 00h					;check for the LoadLibraryFlag, is "test r13, r13" better?
		jne _CallLoadLibrary
		pop rbp							;pop registers used by function
		pop r15
		pop r14

		pop r9							;pop parameters to looked up function
		pop r8
		pop rdx
		pop rcx
		;may need to "sub rsp, 20h" to make shadow space for function
		sub rsp, 20h
		call rax
		add rsp, 20h
		ret

	_Forwarded:
		
		;rsi is only set here which means that after returning from ParseDllHeader to CallLoadLibrary
		;rax = LoadLibrary
		;rsi = forwarded function name
		add rax, r11					;ImageBaseAddress + AddressOfFunctions[FunctionOrdinal*04h]
		mov rsi, rax					;rsi is used ScanFor2E
		_LookupLoadLibrary:
			;TODO: check if requested dll is already present in _PED_LDR_DATA (need to write a UNICODE_STRING hasher)
			mov r9, qword ptr gs:[60h]	;PEB
			mov r9, qword ptr[r9+18h]	;PEB->Ldr (_PEB_LDR_DATA)
			lea r9, qword ptr[r9+10h]	;_PEB_LDR_DATA->InLoadOrderModuleList (LDR_DATA_TABLE_ENTRY)
			mov r9, qword ptr[r9]		;_LIST_ENTRY->Flink (_LIST_ENTRY)
			mov r9, qword ptr[r9]		;_LIST_ENTRY->Flink (_LIST_ENTRY)
			mov r9, qword ptr[r9]		;_LIST_ENTRY->Flink (_LIST_ENTRY)
    
			;save the base address (kernel32)
			mov r11, [r9+30h]

			;qwLoadLibraryHash
			mov r13, 00b9a3b50901ed9addh;set qwHashComparison
			xchg r10, r13				;this is required because in the case of qwLookupMode == 0 ie LOOKUP_BY_NAME
										;this saves the requested qwHash to r13 for use later
			jmp _ParseDllHeader
	
	_CallLoadLibrary:
		
		;if CallLoadLibrary is jumped to it means that a forwarded function was requested and the code has ALREADY
		;	1. looked up the address of LoadLibrary - which is now in rax
		;	2. initialised rsi to point to the forwarder string
		xor rcx, rcx
		_ScanFor2E:
			cmp byte ptr[rsi+rcx], 2Eh
			lea rcx, qword ptr[rcx+01h]	;lea does not effect flags, putting the increment here means
		jne _ScanFor2E					;[rsi+rcx] points to "2Eh"

		mov r12, rcx
		add r12, 0Ch					;0Ch = 04h ("dll\0") + 07h (rounding up to multiple of 08h)
		and r12, 0fffffff8h				;see StackOverflow answer

		sub rsp, r12					;reserve stack space for dll name
		mov rdi, rsp
		
		;can i optimise this to avoid having to push and pop rax?
		;	1. move it to a different register before this point?
		;	2. implement my own string instructions
		push rax
		_CopyForwarderString:
			lodsb
			stosb
		loop _CopyForwarderString
		pop rax

		;write "dll\0"
		mov dword ptr[rdi], 006c6c64h

		;hash from rsi to /0
		mov rdx, 5381d					;could use edx here if it is shorter
		_HashLoop2:
			mov rbx, rdx
			shl rdx, 5
			add rdx, rbx
			xor dl, byte ptr[rsi]		;xor with each character
			inc rsi
			cmp byte ptr[rsi], 00h		;check for null termination
		jne _HashLoop2
		mov r13, rdx

		;current situation:
		;r10 is the hash of the forwarded function
		;r11 is kernel32.dll ImageBaseAddress
		;r12 is the size of stack space reserved by dll name

		mov rcx, rsp					;lpLibFileName
		_CallLoadLibraryDirect:
			;if CallLoadLibraryDirect is jumped to the following conditions must be true:
			;	1. rcx points to either:
			;		a. parsed forwarder string
			;		b. passed lpLibFileName when qwLookupMode == 0
			;2. r12 needs to be 0 to preserve the stack (if we arrived at CallLoadLibraryDirect from CallLoadLibrary then r12 
			;	will be initialised with the number of bytes reserved on the stack

			;annoyingly r10 gets destroyed by LoadLibrary
			;we need to hash calculated in CallLoadLibrary to survive this
			;so after LoadLibrary is called we can pass the hash and ImageBaseAddress to ParseDllHeader
			sub rsp, 20h				;reserve shadow space for four registers (20h = 08h * 04h)
			call rax					;LoadLibraryA
			add rsp, 20h				;restore stack
			add rsp, r12				;remove lpLibFileName / dll name from stack

			;we have now called LoadLibrary so we need to do the following:
			;after calling LoadLibrary for when qwLookupMode == 0
			;if the function is also forwarded then it will jump to CallLoadLibrary
			;if the function is not forwarded then it will be called
			;
			;when qwLookupMode == 1
			;if we are calling LoadLibrary the function is forwarded
			;
			;this means that if RIP is here the function was forwarded or we are calling directly.
			;if we are calling directly we need to make r12 == 0 when it's LOOKUP_BY_NAME
			mov r11, rax			;rax is the return value of LoadLibrary -> ImageBaseAddress
			mov r10, r13			;LookupLoadLibrary exchanges r10 and r13, put the original qwHash back into r10
			mov r12, r13			;make qwLookupMode != 0 so that we don't attempt to LoadLibrary again
			xor r13, r13			;clear qwLoadLibraryFlag so we don't attempt to call LoadLibrary again
			jmp _ParseDllHeader

	_Failed:
		xor r10, r10
		pop rbp						;pop registers used by function
		pop r15
		pop r14

		pop r9						;pop parameters to looked up function
		pop r8
		pop rdx
		pop rcx
		ret
funcCallFunctionByHash endp

END
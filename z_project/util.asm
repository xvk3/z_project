uril segment read execute

;utilHash
;          rcx - null terminated string
utilHash proc

  push rcx
  push rdx
  mov eax, 1505h
  _Loop:
    mov rdx, rax
    shl rax, 05h
    add rax, rdx
    xor al, byte ptr[rcx]
    inc rcx
    cmp byte ptr[rcx], 00h
  jne short _Loop
  pop rdx
  pop rcx

utilHash endp

;utilRand
;          remarks - returns qword in rax
utilRand proc

  xor eax, eax
  inc ax
  cpuid
  test ecx, 1Eh
  jne _NotSupported

  rdrand eax
  test eax, eax
  jz _NotSupported

  _NotSupported:
    rdtsc
    mov cx, ax
    _Loop:
      rol rdx, 01h
      add rax, rdx
      shl rax, 07h
      ror rax, 02h
      xor rax, rdx
      mul rax
      and rax, 0c4fb1e6h
      dec cx
    jnz _Loop
  ret

utilRand endp

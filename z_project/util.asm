uril segment read execute

utilHash proc


utilHash endp


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
      add rax, rdx
      shl rax, 07h
      ror rax, 02h
      xor rax, rdx
      mul rax
      and rax, 0c4fb1e6h
      rol rdx, 01h
      dec cx
    jnz _Loop
  ret

utilRand endp

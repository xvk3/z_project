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

;utilHashSuper
;         rcx - null terminated string
;         rdx - salt
utilHashSuper proc

  push rcx
  push rdx
  push r8
  push r9
  mov eax, 1505h
  mov r8, 0AF23h
  _OuterLoop:
    xor r9, r9
    _Loop:
      shl rax, 05h
      add rax, rdx
      xor al, byte ptr[rcx+r9]
      mov rdx, rax
      inc r9
      cmp byte ptr[rcx+r9], 00h
    jne short _Loop
    dec r8
  jnz _OuterLoop
  pop r9
  pop r8
  pop rdx
  pop rcx
  ret

utilHashSuper endp

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
      ; TODO: fix the explosion algo
      ; use utilExplodeSeed in a loop?
      ; need a verison of utilExplodeSeed that returns qword
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


;utilDecode
;           rcx - lpBuffer
;           rdx - qwLength
;           r8  - qwHash
utilDecode proc

  ; loop over A-Z
  ;  encode each char checking output against lpBuffer
  ;  if an encoded match is found the plaintext is simply the char
  ;  passed to encode

utilDecode endp

;utilEncode
;           rcx - lpBuffer
;           rdx - qwLength
;           r8  - qwHash
utilEncode proc

  mov r9, rcx
  lea r10, [rcx+rdx]

  _Loop:

    movzx rax, byte ptr[r9]

    ; imul
    ; One-operand form: imul [source]
    ; RDX:RAX = RAX * source
    imul r8

    mov rcx, rax
    call utilExplodeSeed
    mov rcx, rax
    call utilQwordToAsciiAZ
    mov byte ptr[r9], al   
 
    inc r9
    cmp r9, r10
  jne _Loop

  ret

utilEncode endp

;utilQwordToAsciiAZ
; TODO: make a version of this that takes the divisor as a parameter
;           rcx - qwSeed
utilQwordToAsciiAZ proc

  mov rax, rcx
  xor rdx, rdx
  mov rcx, 1Ah    ; 26d
  div rcx         ; qwSeed / 26
  mov rax, rdx    ; remainder 0-25 
  add rax, 41h    ; remainder += 65d
  ret

utilQwordToAsciiAZ endp

;utilExplodeSeed - 
;           rcx - qwSeed
utilExplodeSeed proc

  ; imul
  ; Three-operand form: imul [destinaton], [source1], [source2]
  ; destination = source1 * source2
  imul rax, rcx, 41C64E6Dh
  add rax, 3039h
  shr rax, 10h    ; divide rax by 2^16 (65,536)
  xor rdx, rdx    ; clear RDX
  mov rcx, 8000h  ; 32,768
  ; div
  ; In 64-bit mode when REX.W is applied, the instruction divides
  ; the unsigned value in RDX:RAX by the source operand and stores
  ; the quotient in RAX, the remainder in RDX
  ;
  div rcx
  mov rax, rdx    ; return the remainder
  ret

utilExplodeSeed endp

END

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

  push rcx
  push rdx
  push r8

  xor eax, eax
  inc ax
  cpuid
  test ecx, 1Eh
  jne _NotSupported

  rdrand eax
  ; check CF instead of eax, eax
  test eax, eax
  jz _NotSupported

  ; rdrand is supported and worked
  ; ret

  _NotSupported:
    rdtsc
    rol rdx, 04h
    imul rax, rdx, 7FFFFFEDh
    and rax, 0c4fb1e6h
    movzx r8, ax
    _Loop:
      call utilExplodeSeed
      mov rcx, rdx
      dec r8
    jnz _Loop
  mov rax, rdx

  pop r8
  pop rdx
  pop rcx
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

  push rcx
  push rdx
  push r8
  push r9

  mov r9, rcx

  _Loop:
    ; load byte from lpBuffer into al
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
    dec rdx
  jnz _Loop

  pop r9
  pop r8
  pop rdx
  pop rcx
  ret

utilEncode endp

;utilQwordToAsciiAZ
; TODO: make a version of this that takes the divisor as a parameter
;           rcx - qwSeed
utilQwordToAsciiAZ proc

  push rcx
  push rdx
  mov rax, rcx
  xor rdx, rdx
  mov rcx, 1Ah    ; 26d
  div rcx         ; qwSeed / 26
  mov rax, rdx    ; remainder 0-25 
  add rax, 41h    ; remainder += 65d
  pop rdx
  pop rcx
  ret

utilQwordToAsciiAZ endp

;utilExplodeSeed - 
;           rcx - qwSeed
utilExplodeSeed proc

  push rcx
  push rdx
  ; ulong x_rand(ulong qwSeed) {
  ;   ulong rand = seed;
  ;   rand = rand * 1103515245;
  ;   rand = rand + 12345;
  ;   rand = rand / 65536;
  ;   rand = rand % 32768;
  ;   return rand;
  ; }
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

  pop rdx
  pop rcx
  ret

utilExplodeSeed endp

END

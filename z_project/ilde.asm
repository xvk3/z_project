ilde segment read write execute

;is_jmp_tester
is_jmp_tester proc

  _Start:

  xor rcx, rcx
  call is_jmp
  nop

  lea rcx, _0
  call is_jmp
  nop

  lea rcx, _1
  call is_jmp
  nop

  lea rcx, _2
  call is_jmp
  nop

  lea rcx, _3
  call is_jmp
  nop

  lea rcx, _4
  call is_jmp
  nop

  lea rcx, _5
  call is_jmp
  nop

  lea rcx, _6
  call is_jmp
  nop

  lea rcx, _7
  call is_jmp
  nop

  lea rcx, _8
  call is_jmp
  nop

  lea rcx, _9
  call is_jmp
  nop

  lea rcx, _10
  call is_jmp
  nop

  ret

  _0:
    jmp _Start
  _1:
    db 0EEh, 24h
  _2:
    db 70h, 1Ah
  _3:
    db 77h
  _4:
    db 00h
  _5:
    db 07h
  _6:
    jb _Start
  _7:
    jg _Start
  _8:
    jmp _Start
  _9:
    jl _Start
  _10:
    jmp _Start

is_jmp_tester endp


;is_jmp - returns true if the lpOpcode is a jmp (je/jz/ja/jbe etc) instruction
;            rcx - lpOpcode
is_jmp proc

  ;00007FF6A3F16000 EB 24                jmp         lde (07FF6A3F16026h)  
  ;00007FF6A3F16002 70 22                jo          lde (07FF6A3F16026h)  
  ;00007FF6A3F16004 71 20                jno         lde (07FF6A3F16026h)  
  ;00007FF6A3F16006 72 1E                jb          lde (07FF6A3F16026h)  
  ;00007FF6A3F16008 73 1C                jae         lde (07FF6A3F16026h)  
  ;00007FF6A3F1600A 74 1A                je          lde (07FF6A3F16026h)  
  ;00007FF6A3F1600C 75 18                jne         lde (07FF6A3F16026h)  
  ;00007FF6A3F1600E 76 16                jbe         lde (07FF6A3F16026h)  
  ;00007FF6A3F16010 77 14                ja          lde (07FF6A3F16026h)  
  ;00007FF6A3F16012 78 12                js          lde (07FF6A3F16026h)  
  ;00007FF6A3F16014 79 10                jns         lde (07FF6A3F16026h)  
  ;00007FF6A3F16016 7A 0E                jp          lde (07FF6A3F16026h)  
  ;00007FF6A3F16018 7B 0C                jnp         lde (07FF6A3F16026h)  
  ;00007FF6A3F1601A 7A 0A                jp          lde (07FF6A3F16026h)  
  ;00007FF6A3F1601C 7B 08                jnp         lde (07FF6A3F16026h)  
  ;00007FF6A3F1601E 7C 06                jl          lde (07FF6A3F16026h)  
  ;00007FF6A3F16020 7D 04                jge         lde (07FF6A3F16026h)  
  ;00007FF6A3F16022 7E 02                jle         lde (07FF6A3F16026h)  
  ;00007FF6A3F16024 7F 00                jg          lde (07FF6A3F16026h)  

  ; TODO handle jrcxz and loop instructions
  ; -----
  ; e0 00    - loopne 02h
  ; e1 00    - loope  04h
  ; e2 00    - loop   06h
  ; e3 00    - jrcxz  08h
  ; 67 e0 00 - addr32 loopne 02h
  ; 67 e1 00 - addr32 loope  04h
  ; 67 e2 00 - addr32 loop   06h
  ; 67 e3 00 - addr32 jrcxz  08h

  ; TODO handle alternate non-conditional jmp
  ; -----
  ; e9 00 00 00 00
  ;    ^^^^^^^^^^^ rel32 offset to RIP "jmp near" 
  ; eb 00
  ;    ^^          rel08 offset to RIP "jmp short"

  ; checks for jmp opcode
  movzx al, byte ptr[rcx]
  cmp al, 0EBh
  je _Is_Jump

  ; the following instruction normalises all jmp variants (70h -> 7Fh) to be 70h
  and al, 11110000b
  ; 70h = 01110000b
  sub al, 70h
  jz _Is_Jump

  xor rax, rax
  ret

  _Is_Jump:
    xor rax, rax
    inc rax
    ret  

is_jmp endp

;is_call_tester
is_call_tester proc

  lea rcx, _0
  call is_call
  nop

  lea rcx, _1
  call is_call
  nop

  lea rcx, _2
  call is_call
  nop

  lea rcx, _3
  call is_call
  nop

  lea rcx, _4
  call is_call
  nop

  lea rcx, _5
  call is_call
  nop

  lea rcx, _6
  call is_call
  nop

  lea rcx, _7
  call is_call
  nop

  lea rcx, _8
  call is_call
  nop

  lea rcx, _9
  call is_call
  nop

  lea rcx, _10
  call is_call
  nop

  ret

  _0:
    call rax
  _1:
    db 41h, 0ffh, 0d0h
  _2:
    db 0e8h, 00h, 00h, 00h, 00h
  _3:
    call r15
  _4:
    call _0
  _5:
    call rbp
  _6:
    db 41h, 00h
  _7:
    db 41h, 41h
  _8:
    call rsp
  _9:
    db 0ffh, 0d6h
  _10:
    db 0ffh, 0cfh

is_call_tester endp

;is_call - return true if lpOpcode is a call instruction
;            rcx - lpOpcode
is_call proc

  push rcx

  ; if lpOpcode[0] == e8h then it's a jump instruction
  movzx al, byte ptr[rcx]
  cmp al, 0e8h
  je _Is_Call

  ; if lpOpcode[0] != 41h (REX.W prefix) then check same byte for ffh
  cmp al, 41h
  jne _Check_ff

  ; if lpOpcode[0] == 41h then increment lpOpcode (rcx) and check for ffh
  inc rcx
  mov al, byte ptr[rcx]

  ; at this point we are checking either:
  ;  1. lpOpcode[0] (where 41h is not detected)
  ;  2. lpOpcode[1] (in the case where 41h is detected)
  _Check_ff:
    cmp al, 0FFh
  jne _Not_Call

  ; at this point we are checking either:
  ; 1. lpOpcode[1] (where 41h is not detected - but ffh is)
  ; 2. lpOpcode[2] (where 41h and ffh are present)
  movzx al, byte ptr[rcx+01h]
  and al, 11010000b
  sub al, 0D0h
  jz _Is_Call

  _Not_Call:
    pop rcx
    xor rax, rax
    ret

  _Is_Call:
    pop rcx
    xor rax, rax
    inc rax
    ret

is_call endp

;is_push_ret_tester
is_push_ret_tester proc

  lea rcx, _0
  call is_push_ret
  nop

  lea rcx, _1
  call is_push_ret
  nop

  lea rcx, _2
  call is_push_ret
  nop

  lea rcx, _3
  call is_push_ret
  nop

  lea rcx, _4
  call is_push_ret
  nop

  lea rcx, _5
  call is_push_ret
  nop

  lea rcx, _6
  call is_push_ret
  nop

  lea rcx, _7
  call is_push_ret
  nop

  lea rcx, _8
  call is_push_ret
  nop

  lea rcx, _9
  call is_push_ret
  nop

  lea rcx, _10
  call is_push_ret
  nop

  _0:
    push rax
    ret
  _1:
    push rbx
    ret
  _2:
    push rcx
    ret
  _3:
    push rdx
    ret
  _4:
    push r8
    ret
  _5:
    push r9
    ret
  _6:
    push 00h
    ret
  _7:
    push r15
    ret
  _8:
    db 41h, 50h, 0c3h
  _9:
    db 6ah, 00h, 00h, 00h, 00h,
    ret
  _10:
    db 6ah, 00h
    ret

is_push_ret_tester endp

;is_push_ret
;            rcx - lpOpcode
is_push_ret proc

  push rcx

  ; do i need to detect something like "push ax; push cx, push dx; push bx"?
  ; the first 'mov al...' should be a 'movzx'
  movzx al, byte ptr[rcx]

  ; if lpOpcode[0] != 41h (REX.W prefix) then check SAME byte for 'push'
  cmp al, 41h
  jne _Check_Push

  ; if lpOpcode[0] == 41h then increment lpOpcode (rcx) and check for 'push'
  inc rcx
  mov al, byte ptr[rcx]

  ; normalise all push variants (50h -> 57h) to be 50h
  _Check_Push:
    and al, 0101000b
    sub al, 50h
  jz _Check_Ret

  pop rcx
  xor rax, rax
  ret

  _Check_Ret:
    cmp byte ptr[rcx+01h], 0c3h
  je _Is_Push_Ret
  
  pop rcx
  xor rax, rax
  ret

  _Is_Push_Ret:
    pop rcx
    xor rax, rax
    inc rax
    ret

is_push_ret endp

;lde - returns the instruction length in rax
;            rcx - lpOpcode
;            rdx - Architecture ( 0 = x86, 64 = x64)
lde proc

  db 055h, 048h, 083h, 0ECh, 02Bh, 048h, 089h, 0E5h, 051h, 052h, 056h, 0E8h, 000h, 021h, 000h, 000h
  db 0EFh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E5h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 006h, 022h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A5h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0C6h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0BFh, 02Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 065h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 086h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 025h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 046h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E5h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 006h, 021h, 000h, 000h, 000h, 000h, 000h, 000h
  db 098h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A5h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 0C6h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 058h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 065h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 086h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 018h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 025h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 046h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0D8h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 097h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 08Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 087h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 07Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 077h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 06Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 067h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 05Fh, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 028h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 020h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 018h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 010h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 008h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0F8h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0F0h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 080h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 078h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 070h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 068h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 060h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 058h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 050h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 048h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 040h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 038h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 030h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 028h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 020h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 018h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 010h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 008h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0F8h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 016h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A8h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0A0h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 026h, 000h, 000h, 000h, 000h, 000h, 000h, 00Ah, 027h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 098h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B5h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 006h, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 098h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 090h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 088h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 085h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 07Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 075h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 06Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 065h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 05Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 055h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 04Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 045h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 03Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 035h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 02Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 025h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 01Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 015h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 00Dh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Eh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 020h, 000h, 000h, 000h, 000h, 000h, 000h
  db 068h, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 046h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BFh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0B7h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Fh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Fh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0AEh, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 080h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 078h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 070h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 068h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 060h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 058h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 050h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 048h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 040h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 038h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0F1h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 028h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 020h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 018h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 010h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 008h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 055h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 05Fh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 045h, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h, 04Fh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E0h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0D8h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0D0h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0C8h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0C5h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0E6h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B0h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0A8h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 098h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 090h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 088h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 085h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 07Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 075h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 06Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 065h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 05Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 055h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 04Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 080h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 078h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 070h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 068h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 060h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 058h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 050h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 048h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Eh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 056h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0E8h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 006h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0FEh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Eh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0B4h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DAh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0B8h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0A8h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 09Dh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 088h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 068h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 060h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 050h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 048h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0F2h, 024h, 000h, 000h, 000h, 000h, 000h, 000h, 022h, 025h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B5h, 025h, 000h, 000h, 000h, 000h, 000h, 000h, 011h, 026h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Ah, 026h, 000h, 000h, 000h, 000h, 000h, 000h, 0D6h, 026h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Ah, 027h, 000h, 000h, 000h, 000h, 000h, 000h, 08Bh, 027h, 000h, 000h, 000h, 000h, 000h, 000h
  db 005h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 0FDh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0F5h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0EDh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E5h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0DDh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0D5h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0CDh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EEh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0E6h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B8h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0ADh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 098h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 090h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 088h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 048h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 078h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E7h, 022h, 000h, 000h, 000h, 000h, 000h, 000h, 029h, 023h, 000h, 000h, 000h, 000h, 000h, 000h
  db 060h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 058h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FBh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 040h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 038h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 030h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 028h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 020h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 018h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 091h, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0ABh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0D8h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0D0h, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 0C8h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0C0h, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 0B8h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0A8h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 090h, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DCh, 020h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 019h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 019h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 038h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 030h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 028h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 020h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Fh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Fh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 080h, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 078h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 070h, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 068h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 060h, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 058h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B9h, 021h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BFh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0B7h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0B7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ABh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 0A3h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 07Dh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 001h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 048h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Eh, 016h, 000h, 000h, 000h, 000h, 000h, 000h, 026h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 010h, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 008h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 0F8h, 016h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FEh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0F6h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EEh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0E6h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DEh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0D6h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CEh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0C6h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BEh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0B6h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 015h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 000h, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0F8h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0F0h, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Eh, 015h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 017h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 017h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0C0h, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 0B8h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B0h, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 066h, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 038h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B5h, 018h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BFh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 06Fh, 018h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0C0h, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0B8h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B0h, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0A8h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0A0h, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 098h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 090h, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 088h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0E7h, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0F7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 067h, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 0B7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 087h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0dbh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 067h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 057h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 047h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 037h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 027h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 017h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0E7h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0D7h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0C7h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0B7h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0AFh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0A7h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Fh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 097h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 014h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 014h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Bh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Bh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 063h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 053h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Fh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 007h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FFh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Bh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 003h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FBh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0F3h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EBh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0E3h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CBh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0C3h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BBh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0B3h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 013h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 013h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 083h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 073h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 063h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 053h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 043h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 033h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 023h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 013h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Bh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 003h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 012h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 012h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 011h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 011h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 010h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 00Fh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 00Eh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 00Dh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 005h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0FDh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Ch, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CBh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0C3h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BBh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0B3h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ABh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0A3h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Bh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 077h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Bh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 063h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Bh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 053h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Bh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 003h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FBh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 00Bh, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Bh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 003h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FBh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 00Ah, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Bh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 003h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FBh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0F3h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 009h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 009h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 008h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 008h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 007h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 007h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 006h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 006h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 065h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 055h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 045h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 035h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 025h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 015h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 005h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 005h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FDh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0F5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0EDh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0E5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DDh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0D5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CDh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0C5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BDh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0B5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ADh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 0A5h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Dh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 095h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 085h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 07Dh, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 075h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ACh, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 0A4h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 09Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 094h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 08Dh, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 0AFh, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0B3h, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 074h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 06Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 064h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 054h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 04Dh, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 044h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 03Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 034h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 02Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 024h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 01Ch, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 014h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 00Dh, 001h, 000h, 000h, 000h, 000h, 000h, 000h, 004h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0FCh, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0F4h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0ECh, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0E4h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0DCh, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0D4h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0CCh, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0C4h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 0BCh, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0B4h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
  db 05Eh, 051h, 08Fh, 045h, 023h, 089h, 055h, 01Eh, 0C6h, 045h, 022h, 000h, 0C7h, 045h, 002h, 020h
  db 000h, 000h, 000h, 0C7h, 045h, 006h, 020h, 000h, 000h, 000h, 083h, 07Dh, 01Eh, 040h, 075h, 007h
  db 0C7h, 045h, 006h, 040h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h, 008h, 048h
  db 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 05Eh, 05Ah, 059h, 048h, 083h, 0F8h, 0FFh, 074h
  db 007h, 048h, 08Bh, 045h, 023h, 048h, 029h, 0C8h, 048h, 083h, 0C4h, 02Bh, 05Dh, 0C3h, 0C7h, 045h
  db 01Ah, 000h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 025h, 0C7h, 000h
  db 000h, 000h, 0B9h, 040h, 000h, 000h, 000h, 048h, 031h, 0D2h, 0F7h, 0F1h, 089h, 045h, 00Ah, 083h
  db 0F8h, 001h, 075h, 004h, 083h, 045h, 01Ah, 001h, 083h, 0F8h, 002h, 075h, 004h, 083h, 045h, 01Ah
  db 004h, 089h, 055h, 00Eh, 0C1h, 0E0h, 006h, 048h, 001h, 0F0h, 048h, 005h, 000h, 020h, 000h, 000h
  db 048h, 08Dh, 004h, 0D0h, 048h, 003h, 000h, 0FFh, 0D0h, 0C3h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h
  db 040h, 001h, 083h, 0E0h, 038h, 0C1h, 0E8h, 003h, 089h, 045h, 016h, 0C3h, 0C3h, 083h, 07Dh, 006h
  db 020h, 07Ch, 023h, 083h, 045h, 01Ah, 001h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 002h, 083h
  db 0E0h, 007h, 089h, 045h, 012h, 083h, 07Dh, 012h, 005h, 075h, 00Ah, 083h, 07Dh, 00Ah, 000h, 075h
  db 004h, 083h, 045h, 01Ah, 004h, 0C3h, 0C3h, 083h, 07Dh, 006h, 020h, 07Ch, 005h, 083h, 045h, 01Ah
  db 004h, 0C3h, 0C3h, 083h, 07Dh, 006h, 010h, 075h, 005h, 083h, 045h, 01Ah, 002h, 0C3h, 0C3h, 0E8h
  db 05Ah, 0FFh, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h
  db 048h, 0FFh, 045h, 023h, 0C3h, 048h, 083h, 045h, 023h, 002h, 0C3h, 083h, 07Dh, 002h, 010h, 075h
  db 006h, 0E8h, 0D9h, 0FFh, 0FFh, 0FFh, 0C3h, 0E8h, 051h, 002h, 000h, 000h, 0C3h, 083h, 07Dh, 01Eh
  db 040h, 075h, 006h, 0E8h, 045h, 002h, 000h, 000h, 0C3h, 048h, 0FFh, 045h, 023h, 0C3h, 083h, 07Dh
  db 002h, 020h, 07Ch, 006h, 048h, 083h, 045h, 023h, 005h, 0C3h, 048h, 083h, 045h, 023h, 003h, 0C3h
  db 083h, 07Dh, 002h, 040h, 075h, 006h, 048h, 083h, 045h, 023h, 009h, 0C3h, 083h, 07Dh, 002h, 020h
  db 075h, 006h, 048h, 083h, 045h, 023h, 005h, 0C3h, 048h, 083h, 045h, 023h, 003h, 0C3h, 0E8h, 08Ch
  db 0FFh, 0FFh, 0FFh, 048h, 0FFh, 045h, 023h, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 024h, 0C7h, 045h
  db 002h, 040h, 000h, 000h, 000h, 048h, 0FFh, 045h, 023h, 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h
  db 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 0C7h, 045h, 002h, 020h, 000h, 000h
  db 000h, 0C3h, 048h, 0FFh, 045h, 023h, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 025h, 048h, 0FFh, 045h
  db 023h, 0FEh, 045h, 022h, 080h, 07Dh, 022h, 00Fh, 075h, 006h, 0E8h, 0BEh, 001h, 000h, 000h, 0C3h
  db 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h, 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh
  db 0D0h, 0C3h, 048h, 083h, 045h, 023h, 001h, 0C3h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh
  db 022h, 00Fh, 075h, 006h, 0E8h, 094h, 001h, 000h, 000h, 0C3h, 048h, 08Bh, 045h, 023h, 048h, 00Fh
  db 0B6h, 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 0C3h, 083h, 07Dh, 002h, 020h
  db 07Ch, 00Bh, 0E8h, 0F8h, 0FEh, 0FFh, 0FFh, 048h, 083h, 045h, 023h, 004h, 0C3h, 0E8h, 0EDh, 0FEh
  db 0FFh, 0FFh, 048h, 083h, 045h, 023h, 002h, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 006h, 0E8h, 05Ah
  db 001h, 000h, 000h, 0C3h, 048h, 083h, 045h, 023h, 002h, 0C3h, 048h, 083h, 045h, 023h, 004h, 0C3h
  db 048h, 083h, 045h, 023h, 005h, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 006h, 0E8h, 03Ch, 001h, 000h
  db 000h, 0C3h, 0E8h, 0B8h, 0FEh, 0FFh, 0FFh, 0C3h, 0E8h, 011h, 0FEh, 0FFh, 0FFh, 083h, 07Dh, 00Ah
  db 003h, 075h, 006h, 0E8h, 0A7h, 0FEh, 0FFh, 0FFh, 0C3h, 0E8h, 01Fh, 001h, 000h, 000h, 0C3h, 048h
  db 083h, 045h, 023h, 003h, 0C3h, 083h, 07Dh, 006h, 040h, 075h, 006h, 048h, 083h, 045h, 023h, 009h
  db 0C3h, 048h, 083h, 045h, 023h, 005h, 0C3h, 083h, 07Dh, 006h, 010h, 075h, 006h, 048h, 083h, 045h
  db 023h, 003h, 0C3h, 083h, 07Dh, 006h, 020h, 075h, 006h, 048h, 083h, 045h, 023h, 005h, 0C3h, 048h
  db 083h, 045h, 023h, 009h, 0C3h, 080h, 07Dh, 000h, 001h, 075h, 006h, 0E8h, 05Fh, 0FEh, 0FFh, 0FFh
  db 0C3h, 0E8h, 0D7h, 000h, 000h, 000h, 0C3h, 080h, 07Dh, 000h, 001h, 075h, 006h, 0E8h, 04Dh, 0FEh
  db 0FFh, 0FFh, 0C3h, 080h, 07Dh, 001h, 001h, 075h, 006h, 0E8h, 041h, 0FEh, 0FFh, 0FFh, 0C3h, 083h
  db 07Dh, 002h, 010h, 075h, 006h, 0E8h, 035h, 0FEh, 0FFh, 0FFh, 0C3h, 0E8h, 0ADh, 000h, 000h, 000h
  db 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 006h, 0E8h, 0A1h, 000h, 000h, 000h, 0C3h, 083h, 07Dh, 002h
  db 020h, 075h, 006h, 048h, 083h, 045h, 023h, 007h, 0C3h, 048h, 083h, 045h, 023h, 005h, 0C3h, 0C3h
  db 083h, 07Dh, 002h, 010h, 074h, 011h, 0E8h, 063h, 0FDh, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h
  db 023h, 048h, 083h, 045h, 023h, 006h, 0C3h, 0E8h, 052h, 0FDh, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h
  db 045h, 023h, 048h, 083h, 045h, 023h, 004h, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 006h, 0E8h, 05Ah
  db 000h, 000h, 000h, 0C3h, 083h, 07Dh, 002h, 020h, 075h, 006h, 048h, 083h, 045h, 023h, 007h, 0C3h
  db 048h, 083h, 045h, 023h, 005h, 0C3h, 0E8h, 06Fh, 0FDh, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h
  db 006h, 0E8h, 0B9h, 0FDh, 0FFh, 0FFh, 0C3h, 0E8h, 031h, 000h, 000h, 000h, 0C3h, 083h, 07Dh, 01Eh
  db 040h, 075h, 006h, 048h, 083h, 045h, 023h, 005h, 0C3h, 083h, 07Dh, 002h, 020h, 075h, 006h, 048h
  db 083h, 045h, 023h, 005h, 0C3h, 048h, 083h, 045h, 023h, 003h, 0C3h, 080h, 07Dh, 000h, 001h, 075h
  db 006h, 0E8h, 089h, 0FDh, 0FFh, 0FFh, 0C3h, 0E8h, 001h, 000h, 000h, 000h, 0C3h, 048h, 0B8h, 0FFh
  db 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 01Eh, 040h, 075h, 006h, 0E8h, 0EAh
  db 0FFh, 0FFh, 0FFh, 0C3h, 0E8h, 066h, 0FDh, 0FFh, 0FFh, 048h, 083h, 045h, 023h, 001h, 0C3h, 083h
  db 07Dh, 002h, 020h, 07Ch, 00Bh, 0E8h, 055h, 0FDh, 0FFh, 0FFh, 048h, 083h, 045h, 023h, 004h, 0C3h
  db 0E8h, 04Ah, 0FDh, 0FFh, 0FFh, 048h, 083h, 045h, 023h, 002h, 0C3h, 0E8h, 09Eh, 0FCh, 0FFh, 0FFh
  db 0E8h, 0E5h, 0FCh, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h, 00Ch, 08Bh, 045h, 01Ah, 001h, 045h
  db 023h, 048h, 083h, 045h, 023h, 003h, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 006h, 0E8h, 09Bh, 0FFh
  db 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 083h
  db 07Dh, 002h, 020h, 07Ch, 034h, 0E8h, 064h, 0FCh, 0FFh, 0FFh, 0E8h, 0ABh, 0FCh, 0FFh, 0FFh, 083h
  db 07Dh, 016h, 000h, 075h, 00Ch, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 006h
  db 0C3h, 083h, 07Dh, 016h, 001h, 075h, 006h, 0E8h, 061h, 0FFh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah
  db 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0E8h, 030h, 0FCh, 0FFh, 0FFh, 0E8h, 077h
  db 0FCh, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h, 00Ch, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h
  db 083h, 045h, 023h, 004h, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 006h, 0E8h, 02Dh, 0FFh, 0FFh, 0FFh
  db 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0E8h, 0FCh, 0FBh
  db 0FFh, 0FFh, 0E8h, 043h, 0FCh, 0FFh, 0FFh, 083h, 07Dh, 016h, 001h, 07Eh, 006h, 0E8h, 00Bh, 0FFh
  db 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0E8h
  db 026h, 0FCh, 0FFh, 0FFh, 083h, 07Dh, 016h, 006h, 07Eh, 006h, 0E8h, 0EEh, 0FEh, 0FFh, 0FFh, 0C3h
  db 0E8h, 0C9h, 0FBh, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h
  db 0C3h, 0E8h, 0B8h, 0FBh, 0FFh, 0FFh, 0E8h, 0FFh, 0FBh, 0FFh, 0FFh, 083h, 07Dh, 016h, 005h, 07Eh
  db 006h, 0E8h, 0C7h, 0FEh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h
  db 023h, 002h, 0C3h, 0E8h, 096h, 0FBh, 0FFh, 0FFh, 0E8h, 0DDh, 0FBh, 0FFh, 0FFh, 083h, 07Dh, 016h
  db 000h, 075h, 01Ah, 083h, 07Dh, 00Ah, 003h, 00Fh, 085h, 0ACh, 000h, 000h, 000h, 083h, 07Dh, 00Eh
  db 004h, 00Fh, 08Eh, 0A2h, 000h, 000h, 000h, 0E8h, 091h, 0FEh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h
  db 001h, 075h, 01Ah, 083h, 07Dh, 00Ah, 003h, 00Fh, 085h, 08Ch, 000h, 000h, 000h, 083h, 07Dh, 00Eh
  db 001h, 00Fh, 08Eh, 082h, 000h, 000h, 000h, 0E8h, 071h, 0FEh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h
  db 002h, 075h, 010h, 083h, 07Dh, 00Ah, 003h, 00Fh, 085h, 06Ch, 000h, 000h, 000h, 0E8h, 05Bh, 0FEh
  db 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 00Ch, 083h, 07Dh, 00Ah, 003h, 075h, 05Ah, 0E8h
  db 049h, 0FEh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 004h, 075h, 00Ch, 083h, 07Dh, 00Ah, 003h, 075h
  db 048h, 0E8h, 037h, 0FEh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 005h, 075h, 006h, 0E8h, 02Bh, 0FEh
  db 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 006h, 075h, 00Ch, 083h, 07Dh, 00Ah, 003h, 075h, 02Ah, 0E8h
  db 019h, 0FEh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 007h, 075h, 01Eh, 083h, 07Dh, 00Ah, 003h, 075h
  db 018h, 083h, 07Dh, 01Eh, 040h, 075h, 00Ch, 083h, 07Dh, 00Eh, 000h, 074h, 00Ch, 0E8h, 0FBh, 0FDh
  db 0FFh, 0FFh, 0C3h, 0E8h, 0F5h, 0FDh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h
  db 083h, 045h, 023h, 002h, 0C3h, 0E8h, 0C4h, 0FAh, 0FFh, 0FFh, 0E8h, 00Bh, 0FBh, 0FFh, 0FFh, 083h
  db 07Dh, 016h, 004h, 07Dh, 006h, 0E8h, 0D3h, 0FDh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h
  db 023h, 048h, 083h, 045h, 023h, 003h, 0C3h, 0E8h, 0A2h, 0FAh, 0FFh, 0FFh, 0E8h, 0E9h, 0FAh, 0FFh
  db 0FFh, 083h, 07Dh, 016h, 000h, 075h, 006h, 0E8h, 0B1h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h
  db 002h, 075h, 006h, 0E8h, 0A5h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 006h, 0E8h
  db 099h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 004h, 075h, 006h, 0E8h, 08Dh, 0FDh, 0FFh, 0FFh
  db 0C3h, 083h, 07Dh, 016h, 005h, 075h, 006h, 0E8h, 081h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h
  db 007h, 07Eh, 006h, 0E8h, 075h, 0FDh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h
  db 083h, 045h, 023h, 002h, 0C3h, 0E8h, 090h, 0FAh, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h, 006h
  db 0E8h, 058h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 006h, 0E8h, 04Ch, 0FDh, 0FFh
  db 0FFh, 0C3h, 083h, 07Dh, 016h, 002h, 075h, 011h, 0E8h, 021h, 0FAh, 0FFh, 0FFh, 083h, 07Dh, 00Ah
  db 003h, 074h, 052h, 0E8h, 035h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 006h, 0E8h
  db 029h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 004h, 075h, 011h, 0E8h, 0FEh, 0F9h, 0FFh, 0FFh
  db 083h, 07Dh, 00Ah, 003h, 074h, 02Fh, 0E8h, 012h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 005h
  db 075h, 006h, 0E8h, 006h, 0FDh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 006h, 075h, 011h, 0E8h, 0dbh
  db 0F9h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 074h, 00Ch, 0E8h, 0EFh, 0FCh, 0FFh, 0FFh, 0C3h, 0E8h
  db 0E9h, 0FCh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 003h
  db 0C3h, 0E8h, 004h, 0FAh, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h, 006h, 0E8h, 0CCh, 0FCh, 0FFh
  db 0FFh, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 006h, 0E8h, 0C0h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh
  db 016h, 002h, 075h, 011h, 0E8h, 095h, 0F9h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 074h, 052h, 0E8h
  db 0A9h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 006h, 0E8h, 09Dh, 0FCh, 0FFh, 0FFh
  db 0C3h, 083h, 07Dh, 016h, 004h, 075h, 011h, 0E8h, 072h, 0F9h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h
  db 074h, 02Fh, 0E8h, 086h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 005h, 075h, 006h, 0E8h, 07Ah
  db 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 006h, 075h, 011h, 0E8h, 04Fh, 0F9h, 0FFh, 0FFh, 083h
  db 07Dh, 00Ah, 003h, 074h, 00Ch, 0E8h, 063h, 0FCh, 0FFh, 0FFh, 0C3h, 0E8h, 05Dh, 0FCh, 0FFh, 0FFh
  db 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 003h, 0C3h, 0E8h, 078h, 0F9h
  db 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h, 006h, 0E8h, 040h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh
  db 016h, 001h, 075h, 006h, 0E8h, 034h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 002h, 075h, 015h
  db 0E8h, 009h, 0F9h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 00Fh, 084h, 07Bh, 000h, 000h, 000h, 0E8h
  db 019h, 0FCh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 01Dh, 083h, 07Dh, 002h, 010h, 075h
  db 011h, 0E8h, 0E8h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 074h, 05Eh, 0E8h, 0FCh, 0FBh, 0FFh
  db 0FFh, 0C3h, 0E8h, 0F6h, 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 004h, 075h, 006h, 0E8h, 0EAh
  db 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 005h, 075h, 006h, 0E8h, 0DEh, 0FBh, 0FFh, 0FFh, 0C3h
  db 083h, 07Dh, 016h, 006h, 075h, 011h, 0E8h, 0B3h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 074h
  db 029h, 0E8h, 0C7h, 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 007h, 075h, 017h, 083h, 07Dh, 002h
  db 010h, 075h, 011h, 0E8h, 096h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 074h, 00Ch, 0E8h, 0AAh
  db 0FBh, 0FFh, 0FFh, 0C3h, 0E8h, 0A4h, 0FBh, 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h
  db 048h, 083h, 045h, 023h, 003h, 0C3h, 0E8h, 0BFh, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 016h, 000h, 075h
  db 015h, 0E8h, 068h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 00Fh, 085h, 0A0h, 000h, 000h, 000h
  db 0E8h, 078h, 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 015h, 0E8h, 04Dh, 0F8h, 0FFh
  db 0FFh, 083h, 07Dh, 00Ah, 003h, 00Fh, 085h, 085h, 000h, 000h, 000h, 0E8h, 05Dh, 0FBh, 0FFh, 0FFh
  db 0C3h, 083h, 07Dh, 016h, 002h, 075h, 015h, 0E8h, 032h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h
  db 00Fh, 085h, 06Ah, 000h, 000h, 000h, 0E8h, 042h, 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h
  db 075h, 011h, 0E8h, 017h, 0F8h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 053h, 0E8h, 02Bh, 0FBh
  db 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 004h, 075h, 006h, 0E8h, 01Fh, 0FBh, 0FFh, 0FFh, 0C3h, 083h
  db 07Dh, 016h, 005h, 075h, 011h, 0E8h, 0F4h, 0F7h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 030h
  db 0E8h, 008h, 0FBh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 006h, 075h, 011h, 0E8h, 0DDh, 0F7h, 0FFh
  db 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 019h, 0E8h, 0F1h, 0FAh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h
  db 007h, 07Fh, 007h, 0E8h, 0C6h, 0F7h, 0FFh, 0FFh, 0EBh, 006h, 0E8h, 0DEh, 0FAh, 0FFh, 0FFh, 0C3h
  db 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0E8h, 0F9h, 0F7h, 0FFh
  db 0FFh, 083h, 07Dh, 016h, 000h, 075h, 011h, 0E8h, 0A2h, 0F7h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h
  db 075h, 051h, 0E8h, 0B6h, 0FAh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 001h, 075h, 011h, 0E8h, 08Bh
  db 0F7h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 03Ah, 0E8h, 09Fh, 0FAh, 0FFh, 0FFh, 0C3h, 083h
  db 07Dh, 016h, 002h, 075h, 011h, 0E8h, 074h, 0F7h, 0FFh, 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 023h
  db 0E8h, 088h, 0FAh, 0FFh, 0FFh, 0C3h, 083h, 07Dh, 016h, 003h, 075h, 011h, 0E8h, 05Dh, 0F7h, 0FFh
  db 0FFh, 083h, 07Dh, 00Ah, 003h, 075h, 00Ch, 0E8h, 071h, 0FAh, 0FFh, 0FFh, 0C3h, 0E8h, 06Bh, 0FAh
  db 0FFh, 0FFh, 0C3h, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 048h
  db 0FFh, 045h, 023h, 0C7h, 045h, 002h, 010h, 000h, 000h, 000h, 0FEh, 045h, 022h, 080h, 07Dh, 022h
  db 00Fh, 075h, 006h, 0E8h, 045h, 0FAh, 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h
  db 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 0C7h, 045h, 002h, 020h, 000h, 000h
  db 000h, 0C3h, 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh, 022h, 00Fh, 075h, 006h, 0E8h
  db 019h, 0FAh, 0FFh, 0FFh, 0C3h, 08Bh, 04Dh, 006h, 0D1h, 0E9h, 089h, 05Dh, 006h, 048h, 08Bh, 045h
  db 023h, 048h, 00Fh, 0B6h, 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 08Bh, 05Dh
  db 006h, 0D1h, 0E1h, 089h, 04Dh, 006h, 0C3h, 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh
  db 022h, 00Fh, 075h, 006h, 0E8h, 0E4h, 0F9h, 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h
  db 000h, 03Ch, 0A4h, 074h, 012h, 03Ch, 0A7h, 074h, 00Eh, 03Ch, 0AEh, 074h, 00Ah, 03Ch, 0AFh, 074h
  db 006h, 03Ch, 00Fh, 074h, 002h, 0EBh, 004h, 0C6h, 045h, 000h, 001h, 048h, 08Bh, 045h, 023h, 048h
  db 00Fh, 0B6h, 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h, 0FFh, 0D0h, 0C6h, 045h, 000h, 000h
  db 0C3h, 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh, 022h, 00Fh, 075h, 006h, 0E8h, 09Ah
  db 0F9h, 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 000h, 03Ch, 090h, 074h, 03Eh, 03Ch
  db 0A4h, 074h, 03Ah, 03Ch, 0A5h, 074h, 036h, 03Ch, 0A6h, 074h, 032h, 03Ch, 0A7h, 074h, 02Eh, 03Ch
  db 0AAh, 074h, 02Ah, 03Ch, 0ABh, 074h, 026h, 03Ch, 0ACh, 074h, 022h, 03Ch, 0ADh, 074h, 01Eh, 03Ch
  db 0AEh, 074h, 01Ah, 03Ch, 0AFh, 074h, 016h, 03Ch, 06Ch, 074h, 012h, 03Ch, 06Dh, 074h, 00Eh, 03Ch
  db 06Eh, 074h, 00Ah, 03Ch, 06Fh, 074h, 006h, 03Ch, 00Fh, 074h, 002h, 0EBh, 004h, 0C6h, 045h, 001h
  db 001h, 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h, 008h, 048h, 08Dh, 004h, 0CEh, 048h, 003h, 000h
  db 0FFh, 0D0h, 0C6h, 045h, 001h, 000h, 0C3h, 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh
  db 022h, 00Fh, 075h, 006h, 0E8h, 024h, 0F9h, 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h, 048h, 00Fh
  db 0B6h, 008h, 048h, 08Dh, 084h, 0CEh, 000h, 008h, 000h, 000h, 048h, 003h, 000h, 0FFh, 0D0h, 0C3h
  db 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h, 080h, 07Dh, 022h, 00Fh, 075h, 006h, 0E8h, 0FBh, 0F8h
  db 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h, 048h, 00Fh, 0B6h, 008h, 048h, 08Dh, 084h, 0CEh, 000h
  db 010h, 000h, 000h, 048h, 003h, 000h, 0FFh, 0D0h, 0C3h, 048h, 0FFh, 045h, 023h, 0FEh, 045h, 022h
  db 080h, 07Dh, 022h, 00Fh, 075h, 006h, 0E8h, 0D2h, 0F8h, 0FFh, 0FFh, 0C3h, 048h, 08Bh, 045h, 023h
  db 048h, 00Fh, 0B6h, 008h, 048h, 08Dh, 084h, 0CEh, 000h, 018h, 000h, 000h, 048h, 003h, 000h, 0FFh
  db 0D0h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h
  db 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 011h, 0E8h, 0CDh, 0F5h, 0FFh, 0FFh, 083h, 07Dh, 016h
  db 007h, 07Eh, 006h, 0E8h, 095h, 0F8h, 0FFh, 0FFh, 0C3h, 0E8h, 070h, 0F5h, 0FFh, 0FFh, 08Bh, 045h
  db 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h
  db 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 017h
  db 0E8h, 095h, 0F5h, 0FFh, 0FFh, 083h, 07Dh, 016h, 001h, 075h, 069h, 083h, 07Dh, 016h, 007h, 07Eh
  db 063h, 0E8h, 057h, 0F8h, 0FFh, 0FFh, 0C3h, 03Dh, 0C0h, 000h, 000h, 000h, 07Ch, 056h, 089h, 0C2h
  db 0C1h, 0EAh, 004h, 089h, 0C1h, 083h, 0E1h, 00Fh, 083h, 0FAh, 00Dh, 075h, 00Bh, 083h, 0F9h, 000h
  db 074h, 042h, 0E8h, 036h, 0F8h, 0FFh, 0FFh, 0C3h, 083h, 0FAh, 00Eh, 075h, 037h, 083h, 0F9h, 002h
  db 075h, 006h, 0E8h, 026h, 0F8h, 0FFh, 0FFh, 0C3h, 083h, 0F9h, 003h, 075h, 006h, 0E8h, 01Bh, 0F8h
  db 0FFh, 0FFh, 0C3h, 083h, 0F9h, 006h, 075h, 006h, 0E8h, 010h, 0F8h, 0FFh, 0FFh, 0C3h, 083h, 0F9h
  db 007h, 075h, 006h, 0E8h, 005h, 0F8h, 0FFh, 0FFh, 0C3h, 083h, 0F9h, 00Fh, 075h, 006h, 0E8h, 0FAh
  db 0F7h, 0FFh, 0FFh, 0C3h, 0E8h, 0D5h, 0F4h, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h
  db 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h
  db 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 011h, 0E8h, 0FAh, 0F4h, 0FFh, 0FFh
  db 083h, 07Dh, 016h, 007h, 07Eh, 032h, 0E8h, 0C2h, 0F7h, 0FFh, 0FFh, 0C3h, 03Dh, 0C0h, 000h, 000h
  db 000h, 07Ch, 025h, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h, 0E1h, 00Fh, 083h, 0FAh, 00Eh
  db 075h, 00Bh, 083h, 0F9h, 009h, 074h, 011h, 0E8h, 0A1h, 0F7h, 0FFh, 0FFh, 0C3h, 083h, 0FAh, 00Fh
  db 075h, 006h, 0E8h, 096h, 0F7h, 0FFh, 0FFh, 0C3h, 0E8h, 071h, 0F4h, 0FFh, 0FFh, 08Bh, 045h, 01Ah
  db 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h, 000h
  db 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 01Fh, 0E8h
  db 096h, 0F4h, 0FFh, 0FFh, 083h, 07Dh, 016h, 004h, 074h, 00Eh, 083h, 07Dh, 016h, 006h, 074h, 008h
  db 083h, 07Dh, 016h, 007h, 07Fh, 002h, 0EBh, 041h, 0E8h, 050h, 0F7h, 0FFh, 0FFh, 0C3h, 03Dh, 0C0h
  db 000h, 000h, 000h, 07Ch, 034h, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h, 0E1h, 00Fh, 083h
  db 0FAh, 00Eh, 075h, 015h, 083h, 0F9h, 008h, 07Dh, 020h, 083h, 0F9h, 003h, 074h, 01Bh, 083h, 0F9h
  db 002h, 074h, 016h, 0E8h, 025h, 0F7h, 0FFh, 0FFh, 0C3h, 083h, 0FAh, 00Fh, 075h, 00Bh, 083h, 0F9h
  db 008h, 07Ch, 006h, 0E8h, 015h, 0F7h, 0FFh, 0FFh, 0C3h, 0E8h, 0F0h, 0F3h, 0FFh, 0FFh, 08Bh, 045h
  db 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h
  db 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 011h
  db 0E8h, 015h, 0F4h, 0FFh, 0FFh, 083h, 07Dh, 016h, 007h, 07Eh, 022h, 0E8h, 0DDh, 0F6h, 0FFh, 0FFh
  db 0C3h, 03Dh, 0C0h, 000h, 000h, 000h, 07Ch, 015h, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h
  db 0E1h, 00Fh, 083h, 0FAh, 00Dh, 075h, 006h, 0E8h, 0C1h, 0F6h, 0FFh, 0FFh, 0C3h, 0E8h, 09Ch, 0F3h
  db 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h
  db 01Ah, 000h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h
  db 000h, 000h, 07Fh, 019h, 0E8h, 0C1h, 0F3h, 0FFh, 0FFh, 083h, 07Dh, 016h, 005h, 074h, 008h, 083h
  db 07Dh, 016h, 007h, 07Fh, 002h, 0EBh, 032h, 0E8h, 081h, 0F6h, 0FFh, 0FFh, 0C3h, 03Dh, 0C0h, 000h
  db 000h, 000h, 07Ch, 025h, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h, 0E1h, 00Fh, 083h, 0FAh
  db 00Ch, 075h, 00Bh, 083h, 0F9h, 008h, 07Ch, 011h, 0E8h, 060h, 0F6h, 0FFh, 0FFh, 0C3h, 083h, 0FAh
  db 00Fh, 075h, 006h, 0E8h, 055h, 0F6h, 0FFh, 0FFh, 0C3h, 0E8h, 030h, 0F3h, 0FFh, 0FFh, 08Bh, 045h
  db 01Ah, 001h, 045h, 023h, 048h, 083h, 045h, 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h
  db 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h, 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 011h
  db 0E8h, 055h, 0F3h, 0FFh, 0FFh, 083h, 07Dh, 016h, 007h, 07Eh, 027h, 0E8h, 01Dh, 0F6h, 0FFh, 0FFh
  db 0C3h, 03Dh, 0C0h, 000h, 000h, 000h, 07Ch, 01Ah, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h
  db 0E1h, 00Fh, 083h, 0FAh, 00Dh, 075h, 00Bh, 083h, 0F9h, 009h, 074h, 006h, 0E8h, 0FCh, 0F5h, 0FFh
  db 0FFh, 0C3h, 0E8h, 0D7h, 0F2h, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h, 023h, 048h, 083h, 045h
  db 023h, 002h, 0C3h, 0C7h, 045h, 01Ah, 000h, 000h, 000h, 000h, 048h, 08Bh, 045h, 023h, 00Fh, 0B6h
  db 040h, 001h, 03Dh, 0BFh, 000h, 000h, 000h, 07Fh, 011h, 0E8h, 0FCh, 0F2h, 0FFh, 0FFh, 083h, 07Dh
  db 016h, 007h, 07Eh, 052h, 0E8h, 0C4h, 0F5h, 0FFh, 0FFh, 0C3h, 03Dh, 0C0h, 000h, 000h, 000h, 07Ch
  db 045h, 089h, 0C2h, 0C1h, 0EAh, 004h, 089h, 0C1h, 083h, 0E1h, 00Fh, 083h, 0FAh, 00Ch, 075h, 006h
  db 0E8h, 0A8h, 0F5h, 0FFh, 0FFh, 0C3h, 083h, 0FAh, 00Dh, 075h, 006h, 0E8h, 09Dh, 0F5h, 0FFh, 0FFh
  db 0C3h, 083h, 0FAh, 00Eh, 075h, 010h, 083h, 0F9h, 000h, 074h, 01Bh, 083h, 0F9h, 008h, 07Dh, 016h
  db 0E8h, 088h, 0F5h, 0FFh, 0FFh, 0C3h, 083h, 0FAh, 00Fh, 075h, 00Bh, 083h, 0F9h, 008h, 07Ch, 006h
  db 0E8h, 078h, 0F5h, 0FFh, 0FFh, 0C3h, 0E8h, 053h, 0F2h, 0FFh, 0FFh, 08Bh, 045h, 01Ah, 001h, 045h
  db 023h, 048h, 083h, 045h, 023h, 002h, 0C3h

lde endp

END

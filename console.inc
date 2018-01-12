;input
; rax - value to dump
Console_WriteUInt64:
        test    rax, rax
        jne     .not_zero
        push    rax
        mov     al, '0'
        call    Console_WriteChar
        pop     rax
        ret
.not_zero:
        push    rax rbx rcx rdx
        lea     rcx, [Console_Pow10_UInt64]
        mov     rbx, rax
.loop:
        mov     rax, rbx
        xor     rdx, rdx
        div     qword [rcx]
        test    rax, rax
        jnz     .value_loop

        mov     rbx, rdx
        add     rcx, 8

        cmp     qword [rcx], 0
        jne     .loop
        jmp     .end
.value_loop:
        mov     rax, rbx
        xor     rdx, rdx
        div     qword [rcx]
        add     al, '0'
        call    Console_WriteChar

        mov     rbx, rdx
        add     rcx, 8

        cmp     qword [rcx], 0
        jne     .value_loop
.end:
        pop     rdx rcx rbx rax
        ret

;input
;  rax - value to dump
Console_WriteUInt64Hex:
        push    rax rcx rdx
        mov     rdx, rax
        mov     rcx, 16
.loop:
        rol     rdx, 1
        rcl     rax, 1
        rol     rdx, 1
        rcl     rax, 1
        rol     rdx, 1
        rcl     rax, 1
        rol     rdx, 1
        rcl     rax, 1
        and     rax, 0x0f
        add     rax, '0'
        cmp     rax, '9'
        jbe     .digit
        add     rax, 'a' - '9' - 1
.digit:
        call    Console_WriteChar
        loop    .loop
        pop     rdx rcx rax
        ret

;input
;  al - value to dump
Console_WriteUInt8Hex:
        push    rax rcx rdx
        mov     rdx, rax
        mov     rcx, 2
.loop:
        rol     dl, 1
        rcl     al, 1
        rol     dl, 1
        rcl     al, 1
        rol     dl, 1
        rcl     al, 1
        rol     dl, 1
        rcl     al, 1
        and     rax, 0x0f
        add     rax, '0'
        cmp     rax, '9'
        jbe     .digit
        add     rax, 'a' - '9' - 1
.digit:
        call    Console_WriteChar
        loop    .loop
        pop     rdx rcx rax
        ret

        ;input
;  al - character to put
Console_WriteChar:
        push    rax rcx rdx r8 r9 r10 rbx
        mov     bl, al
        sub     rsp, 0x40
        mov     rcx, STD_OUTPUT_HANDLE
        call    [GetStdHandle]
        mov     rcx, rax
        lea     rdx, [rsp + 0x38]
        mov     [rdx], bl
        mov     r8, 1
        lea     r9, [rsp + 0x30]
        mov     qword [rsp + 0x20], 0
        call    [WriteFile]
        add     rsp, 0x40
        pop     rbx r10 r9 r8 rdx rcx rax
        ret

;input
;  rsi - pointer to string
Console_WriteString:
        push    rax rcx rdx rdi r8 r9 r10 rbp
        sub     rsp, 0x38

        mov     rcx, STD_OUTPUT_HANDLE
        call    [GetStdHandle]
        mov     rbp,rax

        mov     rdi,rsi
        or      rcx,-1
        xor     al,al
        repne   scasb
        neg     rcx
        sub     rcx,2

        mov     qword [rsp + 0x20], 0
        lea     r9, [rsp + 0x30]
        mov     r8, rcx
        mov     rdx, rsi
        mov     rcx, rbp
        call    [WriteFile]

        add     rsp, 0x38
        pop     rbp r10 r9 r8 rdi rdx rcx rax
        ret

;input
;  rsi - pointer to string
;  rcx - buffer size
Console_ReadLine:
        push    rax rcx rdx r8 r9 rbp
        mov     rbp, rsp
        sub     rsp, 0x38

        mov     rcx, STD_INPUT_HANDLE
        call    [GetStdHandle]

        mov     rcx, rax
        mov     rdx, rsi
        mov     r8, [rbp + 8 * 4]
        dec     r8
        lea     r9, [rsp + 0x30]
        mov     qword [rsp + 0x20], 0
        call    [ReadFile]

        mov     rax, [rsp + 0x30]
        mov     byte [rsi + rax], 0

        test    rax, rax
        je      .no_lf
        dec     rax
        cmp     byte [rsi + rax], 10
        jne     .no_lf
        mov     byte [rsi + rax], 0
.no_lf:

        test    rax, rax
        je      .no_cr
        dec     rax
        cmp     byte [rsi + rax], 13
        jne     .no_cr
        mov     byte [rsi + rax], 0
.no_cr:

.end:
        add     rsp, 0x38
        pop     rbp r9 r8 rdx rcx rax
        ret

Console_WriteLine:
        push    rsi
        mov     rsi, Console_String_CRLF
        call    Console_WriteString
        pop     rsi
        ret

Console_Pow10_UInt64:
        dq  10000000000000000000    ;18,446,744,073,709,551,615
        dq  1000000000000000000
        dq  100000000000000000
        dq  10000000000000000
        dq  1000000000000000
        dq  100000000000000
        dq  10000000000000
        dq  1000000000000
        dq  100000000000
        dq  10000000000
        dq  1000000000
        dq  100000000
        dq  10000000
        dq  1000000
        dq  100000
        dq  10000
        dq  1000
        dq  100
        dq  10
        dq  1
        dq  0

Console_String_CRLF db 13, 10, 0
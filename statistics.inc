;input:
;  rsi - pointer to uint32[]
;  rcx - length of array
;output:
;  rax - median
;  rbx - min
;  rdx max
Statistics_Median:
        push    rcx
        sub     rsp, 40
virtual at rsp
  .count rq 1
  .min rq 1
  .max rq 1
  .left_count rq 1
  .right_count rq 1
end virtual

        mov     [.count], rcx
        mov     rbx, -1
        mov     rdx, 0

        xor     rcx, rcx
.minmax_loop:
        mov     eax, [rsi + 4 * rcx]
        cmp     rax, rbx
        jae     .no_min
        mov     rbx, rax
.no_min:
        cmp     rax, rdx
        jbe     .no_max
        mov     rdx, rax
.no_max:
        inc     rcx
        cmp     rcx, [.count]
        jb      .minmax_loop

        mov     [.min], rbx
        mov     [.max], rdx

.iteration_loop:
        mov     rax, [.min]
        add     rax, [.max]
        shr     rax, 1
        cmp     rax, [.min]
        je      .stop
        cmp     rax, [.max]
        je      .stop
        mov     [.left_count], 0
        mov     [.right_count], 0

        xor     rcx, rcx
.item_loop:
        cmp     eax, [rsi + 4 * rcx]
        jb      .right
.left:
        inc     [.left_count]
        jmp     .item_cont
.right:
        inc     [.right_count]
        jmp     .item_cont
.item_cont:
        inc     rcx
        cmp     rcx, [.count]
        jb      .item_loop

        mov     rcx, [.left_count]
        cmp     rcx, [.right_count]
        jb      .choose_right
.choose_left:
        mov     [.max], rax
        jmp     .choosen
.choose_right:
        mov     [.min], rax
        jmp     .choosen
.choosen:
        jmp     .iteration_loop
.stop:
        add     rsp, 40
        pop     rcx
        ret

;input
;  rdi - pointer to uint32[]
;returns
;  rax - first best index
;  rdx - second best index
Statistics_HighestValues:
        push    rcx rsi r8 r9
        mov     rax, -1
        mov     rdx, -1
        xor     rcx, rcx
.loop:
        mov     esi, dword [rdi + 4 * rcx]

        cmp     rax, -1
        je      .set_best_1
        cmp     esi, r8d
        ja      .set_best_1

        cmp     rdx, -1
        je      .set_best_2
        cmp     esi, r9d
        ja      .set_best_2
        jmp     .loop_end

.set_best_1:
        mov     rdx, rax
        mov     r9, r8
        mov     rax, rcx
        mov     r8, rsi
        jmp     .loop_end

.set_best_2:
        mov     rdx, rcx
        mov     r9, rsi
        jmp     .loop_end

.loop_end:
        inc     rcx
        cmp     rcx, 256
        jb      .loop

        pop     r9 r8 rsi rcx
        ret
;input:
;  rsi - memory address
;output:
;  rax - time spent
Memory_MeasureReadTime:
        push    rbx rcx rdx
        mfence
        lfence
        rdtscp
        mov     rbx, rax
        lfence
        test    [rsi], al
        lfence
        rdtscp
        sub     rax, rbx
        pop     rdx rcx rbx
        ret

Memory_BenchmarkCache:
        push    rax rbx rcx rdx rsi
        sub     rsp, CACHE_BENCHMARK_ITERATIONS * 4
virtual at rsp
  .timings rd CACHE_BENCHMARK_ITERATIONS
end virtual

        xor     rcx, rcx
        mov     rsi, Memory_Junk
.miss_loop:
        clflush byte [Memory_Junk]
        mfence
        lfence
        call    Memory_MeasureReadTime
        mov     [.timings + 4 * rcx], eax
        inc     rcx
        cmp     rcx, CACHE_BENCHMARK_ITERATIONS
        jb      .miss_loop

        lea     rsi, [.timings]
        mov     rcx, CACHE_BENCHMARK_ITERATIONS
        call    Statistics_Median
        mov     [Memory_MissTime], rax
        mov     [Memory_MissTimeMin], rbx
        mov     [Memory_MissTimeMax], rdx

        xor     rcx, rcx
        mov     rsi, Memory_Junk
.hit_loop:
        prefetchnta byte [Memory_Junk]
        mfence
        lfence
        call    Memory_MeasureReadTime
        mov     [.timings + 4 * rcx], eax
        inc     rcx
        cmp     rcx, CACHE_BENCHMARK_ITERATIONS
        jb      .hit_loop

        lea     rsi, [.timings]
        mov     rcx, CACHE_BENCHMARK_ITERATIONS
        call    Statistics_Median
        mov     [Memory_HitTime], rax
        mov     [Memory_HitTimeMin], rbx
        mov     [Memory_HitTimeMax], rdx

        mov     rax, [Memory_HitTime]
        add     rax, [Memory_MissTime]
        shr     rax, 1
        mov     [Memory_CutOffTime], rax

        add     rsp, CACHE_BENCHMARK_ITERATIONS * 4
        pop     rsi rdx rcx rbx rax
        ret
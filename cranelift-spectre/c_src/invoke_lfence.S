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
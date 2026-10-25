.text
.globl wwe_cdn_gateway
.def wwe_cdn_gateway; .scl 2; .type 32; .endef
.seh_proc wwe_cdn_gateway
wwe_cdn_gateway:
 pushfq
 .seh_stackalloc 8
 subq $224, %rsp
 .seh_stackalloc 224
 .seh_endprologue
 movq %rax,32(%rsp)
 movq %rcx,40(%rsp)
 movq %rdx,48(%rsp)
 movq %r8,56(%rsp)
 movq %r9,64(%rsp)
 movq %r10,72(%rsp)
 movq %r11,80(%rsp)
 movdqu %xmm0,96(%rsp)
 movdqu %xmm1,112(%rsp)
 movdqu %xmm2,128(%rsp)
 movdqu %xmm3,144(%rsp)
 movdqu %xmm4,160(%rsp)
 movdqu %xmm5,176(%rsp)
 leaq 232(%rsp),%rcx
 call wwe_cdn_observe
 movdqu 96(%rsp),%xmm0
 movdqu 112(%rsp),%xmm1
 movdqu 128(%rsp),%xmm2
 movdqu 144(%rsp),%xmm3
 movdqu 160(%rsp),%xmm4
 movdqu 176(%rsp),%xmm5
 movq 32(%rsp),%rax
 movq 40(%rsp),%rcx
 movq 48(%rsp),%rdx
 movq 56(%rsp),%r8
 movq 64(%rsp),%r9
 movq 72(%rsp),%r10
 movq 80(%rsp),%r11
 addq $224,%rsp
 popfq
 jmp *wwe_cdn_original(%rip)
.seh_endproc

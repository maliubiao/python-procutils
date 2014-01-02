default rel
section .text 
	extern PyMem_Malloc
	extern PyString_FromString 
	global get_cpu_brand 
	global do_cpuid

;PyObject *get_cpu_brand()
;return type: str
get_cpu_brand: 
	;rsp -= 40
	push rbp
	mov rbp, rsp 
	sub rsp, 32 
	;$eax=0, cpuid
	xor eax, eax
	cpuid
	;$ebx, $edx, $ecx->[$esp]
	mov [rsp], ebx
	mov [rsp+4], edx
	mov [rsp+8], ecx 
	mov [rsp+12], word 0x0 
	;return PyString_FromString([$rsp])
	mov rdi, rsp		
	mov rax, 0 
	call PyString_FromString wrt ..plt
	leave	
	ret

;int *do_cpuid(int) 
;return type: int *ptr.
do_cpuid: 
	push rbp
	mov rbp, rsp 
	;save p1
	push rdi
	;$rax = malloc(40)
	mov rdi, 40
	mov rax, 0 
	call PyMem_Malloc wrt ..plt; 
	pop r8
	push rax 
	;$eax=0, cpuid
	mov eax, r8d 
	cpuid
	;copy registers
	pop r8 
	mov [r8], eax
	mov [r8+4], ebx
	mov [r8+8], ecx
	mov [r8+12], edx 
	mov rax, r8
	leave
	ret


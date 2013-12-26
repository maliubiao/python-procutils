default rel
section .text 
	extern PyMem_Malloc
	extern PyString_FromString 
	global get_cpu_brand 
	global get_cpu_feature 

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

;int *get_cpu_feature() 
;return type: int *ptr 
get_cpu_feature: 
	push rbp
	mov rbp, rsp 
	;$rax = malloc(40)
	mov rdi, 40;
	mov rax, 0; 
	call PyMem_Malloc wrt ..plt; 
	push rax
	;$eax=0, cpuid
	mov eax, 0x1 
	cpuid
	;copy registers
	pop r8
	;$eax, $ebx, $ecx, $edx->[$rax]
	mov [r8], eax
	mov [r8+4], ebx
	mov [r8+8], ecx
	mov [r8+12], edx 
	mov rax, r8
	leave
	ret

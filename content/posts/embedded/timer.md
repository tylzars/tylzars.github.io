---
title: "Getting timers working on ARM Cortex-M4F"
date: 2026-03-29T02:43:32-04:00
description: "Part 2 to writing an embedded system"
tags: [embedded, arm, rtos]
---

In the learn how to write an RTOS project I've been chipping away at in the evenings, I reached a crossroads... I need to implement timers. Join me on the trail of figuring out there's a whole lot more to a timer than just counting down!

## Understanding the timer peripheral

Diving into the [datasheet](https://www.ti.com/lit/ds/symlink/tm4c1294ncpdt.pdf) for the chip under programming, the "General-Purpose Timers" (Chapter 13) seems like the perfect place to start. Reading through the first bit of the chapter, you'll learn there is a ton of things this timer can do but I really only need `16- or 32-bit programmable one-shot timer`. Luckily for me, having learned to read lots of datasheets now I can peruse my way through to the "Initialization and Configuration" (Chapter 13.4) section. Typically for any type of on-chip peripheral, I find that there is a subsection dedicated to getting it running in the mode you wish. In the case of this timer, Chapter 13.4.1 is "One-Shot/Periodic Timer Mode" configuration.

On thing to note is that on ARM Cortex-M4F MCUs, you need to enable any peripheral that is going to be used before you can configure/initialize it. To my understanding, this is done to keep power draw at the absolute minimum by preventing a bunch of unused stuff from running constantly.

### Enabling the timer peripheral

This is where section 13.4 comes in handy: `To use a GPTM, the appropriate TIMERn bit must be set in the RCGCTIMER register`. This `RCGCTIMER` register will need to get setup first so that way the peripheral we want is actually running in the chip. In the datasheet, there is a handy link to the page for the `RCGCTIMER` register which gives us the following important infromation:

- Base:     0x400F.E000
- Offset:   0x604
- Type:     RW
- Reset:    0x0000.0000

This is a common format for breaking down the basics of a register in this ARM datasheet. The `Base` field denotes where the entire peripheral starts at in the memory map. This is followed by the `Offset` field which denotes where this specific register is set based off the `Base`. This boils down to `Base + Offset = Register Memory Location`. In this case, if we wanted to write to `RCGCTIMER`, we'd write to `0x400F.E000 + 0x604 = 0x400F.E604`. The `Type` field points out that code can both Read and Write to this register. Finally, `Reset` means that the default state of this register is all 0's when booted cleanly (basically all timers off).

That's the overarching structure for the whole register so the programmer knows at a high level what's going on here and how to get to it. The lower level broken down in the table below:

| BIT   | 7  | 6  | 5  | 4  | 3  | 2  | 1  | 0  |
| ----- | -- | -- | -- | -- | -- | -- | -- | -- |
| Name  | R7 | R6 | R5 | R4 | R3 | R2 | R1 | R0 |
| Type  | RW | RW | RW | RW | RW | RW | RW | RW |
| Reset | 0  | 0  | 0  | 0  | 0  | 0  | 0  | 0  |

This table is the fine details and breaks down at each bit or group of bits what's actually being set. We see the same `Type` and `Reset` fields which carry the same meaning but now for the individual bit and not the whole register. The bit is just the bit offset into the register that the field is at. The `Name` field has a corresponding entry below, we're going to be working with Timer 0 so that's the one we'll break down.

```txt
Name: R0
Description: 16/32-Bit General-Purpose Timer 0 Run Mode Clock Gating Control

Value: 0
Description: 16/32-bit general-purpose timer module 0 is disabled.

Value: 1
Description: Enable and provide a clock to 16/32-bit general-purpose timer module 0 in Run mode.
```

There's a lot of mumbo-jumbo here but this boils down to bit 0 enables or disables the first timer. If we write a 1 to the 0th bit of `RCGCTIMER`, then the first timer will be usable. If a 0 is written there instead, the timer will be disabled.

This was a pretty deep breakdown of reading the datasheet, I found that to be the hardest part of this programming exercise and you'll have to do it a lot. Based off all this, you're probably wondering how the code looks... it's literally one line:

```c
*((volatile uint32_t*)(0x400FE000 + 0x604)) |= (1 << 0);
```

This line might seem pretty confusing but it's really just making sure the 0th bit is set inside `RCGCTIMER`. The C syntactic sugar looks a little odd but better get used to it. To break it down this time, the addition is getting the base of the `RCGCTIMER` register. This base is then casted to be a volatile pointer to 4 bytes (uint32_t will always be 4 bytes) with the volatile preventing the compiler from optimizing out reads or writes from this address. We then dereference this pointer to `RCGCTIMER` to get the actual content at that memory address and set the 0th bit by using an bitwise OR. The OR will always set the bit no matter what state the bit currently is.

Part of the thing is that all the timers should be enableable, the code actually cleans up to be like this:

```c
void enable_timer(uint8_t timer) {
    if (timer > 7) {
        // Not a valid timer
        return;
    }
    // Enable
    SET_BIT(SYSCTL_RCGCTIMER, 1 << timer);
}
```

The user will pass in the timer they wish to enable (0-7), and then we convert that to the correct bit and set it in `RCGCTIMER`. Conversely, to disable a timer: unset the bit with a binary `AND 0`.

### Starting the timer

With the timer now enabled, let's get these timers working!

Section 13.4.1 lays out the whole gameplan for us:

1. Ensure the timer is disabled (the TnEN bit in the GPTMCTL register is cleared) before making any changes.
2. Write the GPTM Configuration Register (GPTMCFG) with a value of 0x0000.0000.
3. Configure the TnMR field in the GPTM Timer n Mode Register (GPTMTnMR):
    - Write a value of 0x1 for One-Shot mode.
    - Write a value of 0x2 for Periodic mode.
4. SNIP SNIP SNIP
5. Load the start value into the GPTM Timer n Interval Load Register (GPTMTnILR).
6. If interrupts are required, set the appropriate bits in the GPTM Interrupt Mask Register (GPTMIMR).
7. Set the TnEN bit in the GPTMCTL register to enable the timer and start counting.
8. Poll the GPTMRIS register or wait for the interrupt to be generated (if enabled). In both cases, the status flags are cleared by writing a 1 to the appropriate bit of the GPTM Interrupt Clear Register (GPTMICR).

We'll go step by step and break down the relevant code at each step and where to find it! However, some important notes are below.

- Any registers mentioned here can be found in Chapter 13.5.
- Tn denotes a generic that lets you swap out `n` for a specific timer in your code.
- Step 4 isn't needed for our simple configuration here and is very verbose so I removed it for clarity.
- Each timer peripheral has its own `Base`. When working with a specific timer, the correct base should be used.
  - For this writeup, we are mainly working with `Timer 0` with a base of `0x4003.0000`.
- As for the timer type, we'll be using `Timer A` as it's 16 bit and all we need.

#### Step 1

First order of business is disabling the timer, don't get this confused with enabling/disabling the timer as a peripheral... this enable/disable is per-timer inside the timer peripheral registers.

The `GPTMCTL` register is at an `Offset` of 0x00C. The bit layout of this register looks like the following:

| BIT   | ...     | 0    |
| ----- | ------- | ---- |
| Field | ...     | TAEN |
| Type  | RW      | RW   |
| Reset | 0       | 0    |

For the sake of ease, I'm going to skip all the non-relevant portions here allowing us to see that the 0th bit is the TnEN bit that the instructions want us to set.

I put both ways of writing this operation in here for ease of understanding but behind the scenes both lines of code are doing the exact same thing. The two ways I've written this are:

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x00C)) &= ~(1 << 0);
// Actual
UNSET_BIT(timer->GPTMCTL, 1 << 0);
```

#### Step 2

The next step is to clear the entire `GPTMCFG` register. No need to worry about bits here, just clear all 4 bytes. The `Offset` for this register is 0x000.

Accomplishing this can be seen in the two lines below:

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x000)) = 0x0;
// Actual
timer->GPTMCFG = 0x0;
```

#### Step 3

Now to configure the time for the correct mode: One-Shot. For this simple timer, one-shot mode will let us turn the timer on and upon it's completion the timer will tell us it's finished. The `GPTMTnMR` register is actually `GPTMTAMR`. is at an `Offset` of 0x004.

The bit breakdown can be seen in the following table:

| BIT   | ...     | 1:0  |
| ----- | ------- | ---- |
| Field | ...     | TAMR |
| Type  | RW      | RW   |
| Reset | 0       | 0    |

The `TAMR` field has the following values it can be set to:

```txt
Name: TAMR
Description: GPTM Timer A Mode

The TAMR values are defined as follows:

Value: 0x0
Description: Reserved

Value: 0x1
Description: One-Shot Timer mode

Value: 0x2
Description: Periodic Timer mode

Value: 0x3
Description: Capture mode

The Timer mode is based on the timer configuration defined by bits 2:0
in the GPTMCFG register.
```

Since we're looking for a one-shot, the we only need to set the 0th bit to 1 and leave the 1st bit alone. Assuming you wanted capture mode, setting both the 0th and 1st bit would be required. Setting the correct bit can be seen below:

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x004)) |= (1 << 1);
// Actual
SET_BIT(timer->GPTMTAMR, 1);
```

#### Step 4

Oops, not important at the moment.

#### Step 5

Next on the docket is putting the actual countdown value into `GPTMTnILR`. In this case, we'll want to put the value into `GPTMTAILR` which is at an `Offset` of 0x028. We're using the timer in 16-bit mode, so we need to only fill the bottom half of the register, but we still need to account for the top 16 bits as well.

Putting the timer value into the `GPTMTAILR` can be done like this:

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x028)) = (uint16_t)time;
// Actual
timer->GPTMTAILR = (uint16_t)time;
```

#### Step 6

I figured that throwing it out to an interrupt would be a good idea, so I did decided to set the flage here to enabled the interrupt to trigger when the timer finishes. This seemed like a great idea in practice but ended up posing a bit of a problem down the road. More about interrupts to come...

We're going to load up `GPTMIMR` at an `Offset` of 0x018 with the correct values. In this case, it's really only `TATOIM` which will trigger an interrupt on time-out (completion).

| BIT   | ...     | 0      |
| ----- | ------- | ------ |
| Field | ...     | TATOIM |
| Type  | RW      | RW     |
| Reset | 0       | 0      |

```txt
Name: TATOIM
GPTM Timer A Time-Out Interrupt Mask

The TATOIM values are defined as follows:

Value: 0
Description: Interrupt is disabled.

Value: 1
Description: Interrupt is enabled.
```

This can be accomplished in the following ways:

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x018)) |= (1 << 0);
// Actual
SET_BIT(timer->GPTMIMR, 1 << 0); 
```

#### Step 7

With all this setup completed, the last step is to just start the timer! We're going to do the inverse of what we did in [Step 1](#step-1) and make that bit into a 1.

```c
// Verbose
*((volatile uint32_t*)(0x40030000 + 0x00C)) |= (1 << 0);
// Actual
SET_BIT(timer->GPTMCTL, 1 << 0);
```

## El Fin... or so you'd think... oops

This goes about as good as you'd expect, absolutely nothing happens when you run this code. The main culprit for that is interrupts...

Since this is a learning project for me and I haven't hit on them yet, I'm going to go over them and break down how to get them running for this code to actually work becuase that's important if we want the timer to actually be usable without constantly polling to see if it has completed.

When I make a new post, I'll link it here? Todoaloo for now. See some base info below..........

## Interrupt Internals

An interrupt is essentially the something pinging the processor and saying "Hey, I need you to take care of this now". In such, the processor will stop the code it's executing and head off to deal with interrupt.

When dealing with interrupts, there are essentially two things to keep track of:

- ISR: Interrupt Service Routine (or Interrupt Handler)
- IRQ: Interrupt Request

After writing the names, I guess they are pretty self explainatory but the ISR will handle an IRQ. Some peripheral, hardware, or functionality will raise an IRQ and then the ISR will run some code to deal with it.

## Bug Fixing

The iterrupt would always fire when enabling the peripheral, simply write a 0 to the timer enable before enabling (turning on) the timer.

## El Fin

This does gloss over some important interrupt functionality, such as priotiry and whatnot but that's something for down the road.

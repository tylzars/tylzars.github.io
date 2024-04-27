---
title: "hitb-gsec-2017 babyqemu"
date: 2024-04-27T12:13:32+05:30
description: "Not sure I enjoy being inside the hypervisor!"
tags: [qemu, escape, pwn]
---

This was an old challenge, but one of my friends was teaching to it and I knew nothing about QEMU and physical hardware. I went into it know it was a QEMU escape so I won't be covering the mindset of finding that out but I'll break down the indepth meaning behind what the exploit does and some of the QEMU internals that make this problem solvable.

## The Problem

The provided resources for the challenge allude to it being a QEMU challenge:

```bash
-rwxr-xr-x    1 sam  staff   281B Jul 11 15:38 launch.sh
drwxr-xr-x   59 sam  staff   2.0K Jul 11 13:36 pc-bios
-rwxr-xr-x    1 sam  staff    38M Jul 11 13:32 qemu-system-x86_64
-rw-r--r--    1 sam  staff   3.7M Jul 11 13:32 rootfs.cpio
-rwxr-xr-x    1 sam  staff   7.0M Jul 11 13:35 vmlinuz-4.8.0-52-generic
```

If you've never used QEMU before, it's an open source emulator that allows for a crazy amount of flexibility and extensibility to run different architectures, machines, and OSs. We can see here we get provided with a compiled `qemu-system-x86_64` binary which is the emulator provided to us. We can also see `pc-bios`, `rootfs.cpio`, and `vmlinuz-4.8.0-52-generic` which look like a generic operating system. We can see how all of these files get wrapped together to spin up an emulated OS by looking inside `launch.sh`; this contains the following:

```bash
#!/bin/sh
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
-device hitb,id=vda
```

A quick line by line breakdown of what's happening here:

1. We launch the `qemu` binary
2. We provide an `initrd` image (Initial RAM Disk)
3. We provide the `kernel` for the OS
4. We `append` our kernel arguments
5. We enable acceleration on the VM with `enable-kvm`
6. There is no screen provided so we throw away the `monitor`
7. The `-m` will let QEMU know there are no graphics and the system has 64Mb of RAM
8. The `-L` passes in the BIOS/UEFI for the device
9. We attach a custom `device` called `hitb` with an ID of `vba`

With that out of the way, go ahead and run `./launch.sh` and see how the image will boot up. After waiting for a minute, you'll be prompted for a username, typing in `root` is enough to keep drop into the shell inside our QEMU VM.

## QEMU Internal

The first part of understanding the solve for this challenge is understanding how QEMU works. This is needed for the reverse engineering work that will be reponsible for the provided custom device. We're gonna dive right into the deep end here and start reversing out this custom device. For decompiling `qemu-system-x86_64` I'll be using [Ghidra](https://github.com/NationalSecurityAgency/ghidra) but there are other alternatives such as Binary Ninja, Cutter, and radare2. Any dissassemble/decompiler will work for the task.

### Initialization

One of the first things we'll notice is that the binary for `qemu-system-x86_64` is not stripped. This is a large win for us as all our functions will have names associated with them allowing us to quickly find out there are quite a few functions that work on our `hitb` device:

```txt
Function name                        Start    Length
-------------                        -----    ------
do_qemu_init_pci_hitb_register_types 00300bf0 00000011
hitb_class_init                      00383e00 0000006F
hitb_dma_timer                       00384090 0000010F
hitb_enc                             00383dd0 0000001E
hitb_fact_thread                     00383f90 000000F9
hitb_instance_init                   00383ed0 00000069
hitb_mmio_read                       00384440 00000148
hitb_mmio_write                      003841a0 000002A0
hitb_obj_uint64                      00383f40 00000011
hitb_raise_irq                       00383f60 0000002B
pci_hitb_realize                     00384590 000000D0
pci_hitb_register_types              00383df0 0000000C
pci_hitb_uninit                      00383e70 00000060
```

These are all the functions mapped into the kernel to work with our `hitb` device. We'll start in order of how QEMU loads up the device. Unsuprisingly, `hitb_class_init` gets called first and will initialize the `hitb` device and call `pci_hitb_realize`. The `pci_hitb_realize` will call a few important functions that actually make the device go.

1. msi_init()
   - Initializes support for Message Signaled Interrupts
2. timer_init_tl
   - Initialzies timer list with new function for our device
3. qemu_mutex_init
   - ???
4. qemu_cond_init
   - ???
5. qemu_thread_create
   - Add a `hitb` thread for concurrect device usages
6. memory_region_init_io
   - Create our MMIO region for reading and writing to `hitb`
7. pci_register_bar
   - ???
  
Looking at the actual decompilation of this function, we can pull some critical information from each of these functions.

Firstly, in the `timer_init_tl` call there is a callback that will execute a function every so often. This call is the following:

```c
timer_init_tl((QEMUTimer *)(pdev[1].io_regions + 4), main_loop_tlg.tl[1], 1000000, hitb_dma_timer, pdev);
```

By checking out the QEMU source ([here](https://github.com/coreos/qemu/blob/ed988a3274c8e08ce220419cb48ef81a16754ea4/include/qemu/timer.h#L414)), we can see that the fourth argument is our callback for when the timer expires. This function will be getting periodically called to execute reads, writes, and other attributes of our `hitb`.

Secondly, the devices physical memory location is initialzed in the `memory_region_init_io` call. The call is the following:

```c
memory_region_init_io((MemoryRegion *)(pdev + 1), (Object *)pdev, &hitb_mmio_ops, pdev, "hitb-mmio", 0x100000);
```

From this call, we can notice the last argument is the size of the MMIO region it allocates for our device: 0x100000. While this isn't vital to know for our escape, it is cool to break down some of what's happening behind the scenes of QEMU.

### Device

With our device initialzed with QEMU, let's break down how we can interact with it through some of the other provided functionality.

A *hitb struct breakdown*

The *hitb functionality*

- `hitb_mmio_read`
- `hitb_mmio_write`
- `hitb_dma_timer`
- `hitb_enc`

## Understand the Physical to Virtual

## Reverse Engineering The Device

## PWNing the Device

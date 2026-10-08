---
title: "Partially Solving the A12 Error in the Ubiquiti EdgeRouter Line Up"
date: 2026-10-07T12:13:32+05:30
description: "The flash chip rumor is mostly correct but there's plenty more that can cause it."
tags: [kernel, system, reverse-engineering]
---

I have an EdgeRouter at home and I have quite enjoyed it for keeping my home internet up and running over the years. Out of the blue, the EdgeRouter started throwing up an "Error A12" in the Web UI.

Looking into this error on the internet revealed some people that had encountered it before on the Unifi forums: [Link 1](https://community.ui.com/questions/Initialization-error-A12/84cd7706-72db-4cb6-87e9-dc7d471da0b3), [Link 2](https://amplifi.community.ui.com/questions/Error-A12-UVC-Dome/2b659453-d12a-45c8-87d5-b5944f8f5423), [Link 3](https://community.ui.com/questions/ERLite-3-Initialization-Error-A12-old-firmware-possible-counterfeit/eba1b8d4-f2c2-44e4-bebd-c5e75790ee1a). The general consensus on every forum was that is was some sort of SPI Flash error that was marking the device as a counterfeit.

There is [one forum](https://www.eevblog.com/forum/buysellwanted/wtb-ubiquiti-poe-edgeswitch-48-flash-chip-mx25l25645g/) that has some more depth but mainly just stating that something in the flash is the cause and it might be some OTP flash bytes that are set directly at the factory.

My EdgeRouter was running `v2.0.8-hotfix.1` during the troubleshooting and writing of this; addresses probably won't track across versions and some functions names may also not track.

[TDLR is at the bottom](#tldr)

## The Symptoms

The device showed the following sign in the Web UI System Menu: red `Error-A12` text in the corner.

I `grepped` the filesystem for `Error-A12` and found it also in these spots:

- An empty file at `/etc/Error-A12`
- `/etc/version` prefixed with `[Error-A12]`
- `Error-A12` in `/proc/sys/kernel/hostname`

Oddly, the error message only shows up in some Web files but there were no string references inside any system binaries or kernel objects. The Web UI calls `/etc/Error-A12` existing `COUNTERFEIT_FILE`. To this point, if everything is to be believed then `Error-A12` is a counterfeit check that lives in the SPI flash.

## Narrowing Down the Source

By the time the board has finished booting and I could SSH into the device, the error had already populated and all occurences of the string were present.

I have been using Claude more and more and figured this would be a fun task to let it handle directly on the hardware, I had a spare router that I switched over to so this one was free real estate for it to brick if it did.

Claude was given two tools: SSH to the device for Linux and console access to the port on the front for uBoot. The first task was getting Claude to make some scripts for interacting with the different protocols... evidently Claude found it easier to just use the console for everything and SSH fell to the wayside.

Along with this, I'm a big fan of GhidraMCP and passed that with the RootFS along to Claude so it can do all the RE it ever wanted. Unifi provides the firmware images for all EdgeRouters which includes the uBoot bootloader and the actual RootFS.

With this all setup, Claude started reasoning and was off to the races.

## Claude's Search

Watching Claude interact directly with hardware is wild. The speed at which information was coming off the device was truly insane. Claude caught something interesting in `dmesg`:

```
[   25.455678] systemd[1]: systemd 232 running in system mode. (+PAM +AUDIT ...)
[   25.460618] systemd[1]: Detected architecture mips64.
[   25.545996] systemd[1]: Set hostname to <EdgeRouter-12>.
[   27.644581] systemd[1]: Listening on Journal Socket (/dev/log).
[   27.659524] systemd[1]: Reached target Swap.
[   27.681794] systemd[1]: Listening on udev Control Socket.
[   29.552823] ubnt_platform: loading out-of-tree module taints kernel.
[   29.554072] ubnt_platform: module license 'Proprietary' taints kernel.
[   29.555186] Disabling lock debugging due to kernel taint
[   29.584232] start to reset chip family-0 on dev_id-0
[   29.586975] wait for finishing reset chip family-0 on dev_id-0
[   32.775233] reset chip family-0 on dev_id-0 OK
[   32.824111] random: crng init done
...
```

During the devices boot, the hostname is set properly to what a user has set it to but something modifies it later in the boot process to append the A12 error message.

Claude figured this meant something in a kernel module was the cause for this. I didn't know this was possible but Claude just did a binary search of the kernel modules by disabling half and then splitting in the middle to find the module that was the problem. Miraculously, this did not brick my EdgeRouter and Claude found the module responsible.

Its bisection process looked something like this:

```bash
# Disable
$ cd /lib/modules/4.9.79-UBNT/extra
$ for m in *.ko; do sudo mv "$m" "$m.disabled"; done
$ sudo rm -f /etc/Error-A12
$ sudo sed -i 's/^\[Error-A12\] //' /etc/version
$ sudo reboot
# Re-enable half
$ sudo mv cavium-ip-offload.ko.disabled cavium-ip-offload.ko
$ sudo mv ubnt_nf_app.ko.disabled ubnt_nf_app.ko
$ sudo mv tdts.ko.disabled tdts.ko
$ sudo mv cvm-ipsec-kame.ko.disabled cvm-ipsec-kame.ko
$ sudo mv ipt_ACCT.ko.disabled ipt_ACCT.ko
$ sudo reboot
```

Drumroll please for the culprit........... `ubnt_platform.ko` and `tdts.ko`. Odd that two different modules cause it to appear but don't fret as this will clear up later.

`ubnt_platform.ko` is the front panel switch driver doing hardware setup, resetting the switch chip, and enabling the front panel ports. On the complete opposite side is `tdts.ko` which is a proprietary deep-packet-inspection driver. These two modules really have no connection it would seem, so why do they cause the `Error-A12` issue?

During testing, it was found that `mpls_fwdr.ko` also carries the same code for setting `Error-A12`. This module does the Multiprotocol Label Switching (MPLS) but on my device it wasn't required to be disabled for the Error to not pop.

## Time for Ghidra!

I figured `ubnt_platform.ko` was subject number one, as it's directly listed in the `dmesg` and will always need to run for the device to function. My EdgeRouter has SSH enabled, so pulling the files off is easy with SFTP. Importing it into Ghidra yields the classic kernel module vibes, a whole lot of exported hardware stuff and a bunch of unnamed functions. However, there are a bunch of exported functions that just have absolute gibberish for 6 characters. As an example, a quick `nm` of the file shows some of these names:

```txt
0000000000002358 b uunee9.95930
0000000000002348 b uunee9.95965
                 U vfree
                 U vfs_read
                 U vfs_write
0000000000045014 b vid_port_map
0000000000000678 t vlan_aware_sh
0000000000001400 t vlan_aware_st
                 U vmalloc
0000000000003478 t Vohnga
0000000000000868 t vsc8504_led_ctrl
0000000000001dd8 t wah7ma
                 U wake_up_process
0000000000000db0 t wiedae
0000000000003ee8 t Xepie5
000000000000a0ec t xoesh7
0000000000002c74 t yai2le
0000000000001b60 t yeeche.part.5
                 U yield
000000000000a934 t yoash4
0000000000000314 t yu0ziw
0000000000000a00 t zoYaeT
```

These 6 letter names were quite curious and when reading through `init_module` after the board and PHY setup one of these functions gets called:

```c
if (1 < board_rev_major - 2) {
  // SNIP
  memset(geigie,0xff,100);
  eet5De();
  uVar12 = ((au0eiM + -0x5e42455) / 3) * 3 + 0x5e42455;
  if ((uVar12 & 0x5e424d3) != uVar12) {
    msleep(1000);
    Iey8oh = ((Iey8oh + -0x5e42455) / 3 + 1) * 3 + 0x5e42455;
    eet5De();
    // SNIP
  }
  // SNIP
}
```

I'm intrigued! <br> ![Time To Go Deeper](./time_to_go_deeper.jpeg)

The beginning of `eet5De` is quite a lot and uses a bunch of custom MIPS instructions that my brain just stubbed for the sake of complexity. I eventually got to this section that seemed to be doing some type of XOR keying:

```c
if (Soe7Se.92526 == 0) { // Is data de-obfuscated already?
  i.92527 = 0;
  do {
    pbVar18 = &nai8Ee.92525 + i.92527; // Get pointer to data
    bVar4 = *pbVar18; // Get obfuscated data
    uVar7 = i.92527 & 3;
    if (bVar4 == 0) break; // Stop on nulls
    i.92527 = i.92527 + 1; // i++
    *pbVar18 = (&fsv_u1)[uVar7] ^ bVar4; // Store de-obfuscated data back
  } while (i.92527 < 0xd);
  Soe7Se.92526 = 1; // Data is de-obfuscated
}
```

As such, this was lifted to Python to see what's actually going on under the hood:

```python
# fsv_u1
key = bytes([0x81, 0x93, 0xe0, 0xc4])

# Kernel Module
data = open('ubnt_platform.ko', 'rb').read()

# Location of data
nai8Ee_92525 = 0x2d2978
base_addr = 0x100000
offset = 0x2d2978 - 0x100000

# Loop runs 0xd times
section = data[offset : offset + 0xd]
for seg in section.split(b'\x00'):
    if seg:
        print(bytes(b ^ key[i % 4] for i, b in enumerate(seg)))
```

This outputs some new data:

```
b'\xe0\xe1\x84\xad\xef\xf4' -> b'arding'
b'\xae\xe3\x92\xab\xe2'     -> b'/proc'
```

![GreatSuccess](./great_success.png)

In a stroke of genius laziness, bruteforcing this key over the entire `.data` sections yields 18 new strings:

```
.data+0x0558: /tmp/tmp.YfvXa7Q2QO
.data+0x0570: /etc/passwd
.data+0x0580: /var/etc/dropbear/authorized_keys
.data+0x05a8: /var/etc/persistent/mcuser/.ssh/authorized_keys
.data+0x05e0: /var/etc/persistent/.ssh/authorized_keys
.data+0x0610: /etc/version
.data+0x0620: [Error-A12]
.data+0x0630: /etc/Error-A12
.data+0x0640: /etc/persistent/Error-A12
.data+0x0660: /proc/sys/kernel/hostname
.data+0x0680: Error-A12
.data+0x0690: /proc/sys/kernel/domainname
.data+0x06b0: /proc/sys/kernel/printk_ratelimit
.data+0x06d8: /proc/sys/net/ipv4/conf/all/forwarding
.data+0x0700: /proc/sys/net/ipv4/ip_forward
.data+0x0720: /etc/board.info
.data+0x0738: board.sysid
.data+0x0748: board.cpurevision
```

W! The `[Error-A12]` strings are all obfuscated in the kernel modules which is why they're not present anywhere on disk. This actually does miss a string though, the lazy method catches a `0x09` byte trailing for an integer that causes the keying to be off for a future read of `.data+0x04f8: /dev/mtdblock`. The following code uses four byte alignment to prevent exactly that.

```python
key = bytes([0x81,0x93,0xe0,0xc4])
data = open('ubnt_platform.ko','rb').read()[0x1d2280 : 0x1d2280 + 0x2710]
i = 0
while i < len(data) - 1:
    # Get index of end of potential string
    n = data.index(b'\x00', i)
    if n > i:
        # Decrypt
        print(f'{i:04x}', bytes(b ^ key[j & 3] for j, b in enumerate(data[i:n])))
    # Loop
    i = (n + 4) & ~3
```

I would assume this was actually done to prevent anyone from figuring out where the check actually lives to ensure the EdgeRouter is genuine. Some of the strings seem unrelated to the genuine check though and I didn't investigate further about what the obfuscated SSH key strings are used for. Back on task... with the obfuscated string memory address now known, time to map them back to the actual code doing the check.

## The Truth of the Matter

Due to the obfuscation, the Ghidra code is all over the place. Functions in functions, meaningless names, random globals, custom MIPS instructions, just absolute chaos. The code snippets for the rest of the write-up will be using my cleaned up naming and function flow, but I will include addresses for reference assuming this is ever put in Ghidra again.

The trail starts in `init_module` which now shows a different picture at the bottom:

```c
// 0x27efbc
g_dwEarlyOutCookie = 0x5e424d3;
g_dwCheckPassCookie = 0x5e42455;
memset(g_abTamperState, 0xff, 100);
CheckDeviceAuthenticity(); // Check #1
uVar12 = ((g_dwEarlyOutCookie + -0x5e42455) / 3) * 3 + 0x5e42455;
if ((uVar12 & 0x5e424d3) != uVar12) {
    msleep(1000);
    g_dwCheckPassCookie = ((g_dwCheckPassCookie + -0x5e42455) / 3 + 1) * 3 + 0x5e42455;
    CheckDeviceAuthenticity(); // Check #2
    msleep(1000);
    g_dwCheckPassCookie = ((g_dwCheckPassCookie + -0x5e42455) / 3 + 1) * 3 + 0x5e42455;
    CheckDeviceAuthenticity(); // Check #3
    msleep(1000);
    g_dwCheckPassCookie = ((g_dwCheckPassCookie + -0x5e42455) / 3 + 1) * 3 + 0x5e42455;
    CheckDeviceAuthenticity(); // Mark as Genuine or Not
}
```

The authenticity functionality that sets `Error-A12` is called 4 times, this is actually because it needs to fail the same set of checks four times in a row to fail the genuine device check. On the fourth pass, the kernel module will either continue booting as if the device is genuine or mark it as non-genuine by setting the previously noted symptoms. However, if the device passes with flying colors on the first call, the `if` statement skips the next three calls.

![on my way to see if that's a genuine flash chip](./flash_meme.png)

`CheckDeviceAuthenticity` (0x279500) is a massive function, about 1300 lines in Ghidra, so to keep this short and sweet all code that is repeated a ton will be squashed to a comment block. 

The first check is that the board model read from the SPI flash block `mtdblock2` is in the "genuine" set.

```c
uVar2 = ReadFlashByteAt(0xa000); // Read from mtdblock2 at offset 0xa000
if ((0x12 < uVar2) || ((1L << (long)(char)uVar2 & 0x7ffd2U) == 0)) {
  /* FAIL: board/model ID at mtdblock2 + 0xa000 is not in the accepted set {01,04,06-12} */
}
```

From the output of `cat /proc/mtd`, we can see that `mtdblock2` is labelled as `eeprom`:

```bash
dev:    size   erasesize  name
mtd0: 00200000 00001000 "boot0"
mtd1: 00200000 00001000 "boot1"
mtd2: 00010000 00001000 "eeprom"
```

The second check is that the JEDEC ID read from the chip is the same stored in the flash that Linux can access on `mtdblock2`.

```c
iVar13 = ReadFlashDwordAt(0xa02e); // Read from mtdblock2 at offset 0xa02e
g_dwLiveJedecId = -1;
g_dwLiveJedecId = ReadFlashJedecId(); // Run SPI command 0x9F against chip via TransferSpiCommand
if (iVar13 != g_dwLiveJedecId) {
  /* FAIL: live RDID JEDEC ID != JEDEC ID stored in the flash record at mtdblock2 + 0xa02e */
}
```

The third check is reading the one-time-programmable (OTP) bytes from the flash chip. This involves checking the manufacturer ID again for the chip the board will speak to as each manfacturer has a custom implementation and sequence of bytes to read/write the OTP section of a flash chip. When the ER12 boots, it prints `SPI ID: c2:20:17:c2:20` to the console leading directly to the correct path here. Upon entering the right path, the kernel module will enter the security mode and read the bytes from the OTP storing them into `g_pOtpCompareBuf->otp_read`.

```c
pOVar6 = (OtpCompareBuf *)kmem_cache_alloc(_simple_strtoul, 0x2088020);
g_pOtpCompareBuf = pOVar6;
if (pOVar6 != (OtpCompareBuf *)0x0) {
  LoadReferenceBlob(pOVar6, 0x80, 0xa033, 0x80); // Read 0x80 from mtdblock2 + 0xa033
  bVar15 = ReadFlashByteAt(0xa032); // Read 0x1 from mtdblock2 + 0xa032
  pOVar4 = g_pOtpCompareBuf;
  pOVar6->reference_len = bVar15; // Length of OTP data to read
  g_cbOtpObtainedCopy = 0;
  g_dwCheckedJedecId = 0;
  g_cbOtpRequested = 0;
  g_cbOtpObtained = 0;
  memset(pOVar4->otp_read, 0xff, 0x80);
  // Get JEDEC ID from chip and check against full manufacturer IDs
  g_dwCheckedJedecId = ReadFlashJedecId();
  if ((g_dwCheckedJedecId == 0xc22535 || g_dwCheckedJedecId == 0xc22014) ||
      (g_dwCheckedJedecId - 0xc22017 < 3 || g_dwCheckedJedecId == 0xc22015)) {
    g_cbOtpRequested = 0x40;
    memset(&g_bFlashSecurityReg,0,1);
    TransferSpiCommand(g_abSpiCmdRdscur,1,&g_bFlashSecurityReg,1);
    if (((ulong)g_bFlashSecurityReg & 3) == 3) {
      if (g_cbOtpRequested < 0x81) {
        ReadFlashOtpRegion(pOVar4->otp_read);
        g_cbOtpObtained = g_cbOtpRequested;
      }
    }
  } else {
      /* Check a whole lot of other SPI Chips */
  }

  g_cbOtpObtainedCopy = g_cbOtpObtained;
  pOVar6 = g_pOtpCompareBuf;
  pOVar4->obtained_len = (byte)g_cbOtpObtained;
  
  /* Obtained the correct number of bytes from the OTP and they match the bytes from one flash block against the OTP */
  if ((0x80 < pOVar6->obtained_len) || !(pOVar6->reference_len <= 0x80 &&
        pOVar6->obtained_len == pOVar6->reference_len) || (lVar8 = memcmp(pOVar6->reference, pOVar6->otp_read, pOVar6->obtained_len), lVar8 != 0)) {
    /* FAIL: OTP byte count out of range after the RDSCUR / Secured-OTP read path, OTP read length doesn't match actual mtdblock2 length, or OTP read data doesn't match mtdblock2 data */
  }
}
```

The final check for `Error-A12` is that the board is the correct board again, but this time more specific. If the board ID is not `7`, the device will fail out. If board ID is `7`, some custom MIPS happens and the PRId (MIPS Processor Identification Register) is read and checked against some pre-coded `mtdblock2` offset again.

```c
lVar18 = ReadBoardModelId();
if (lVar18 == 7) {
  iVar13 = ReadFlashDwordAt(0xa0b3);
  if (PRId != iVar13) {
    /* FAIL: CP0 PRId does not match the CPU ID stored at mtdblock2 + 0xa0b3 */
  }
} else {
  /* Handle other Board IDs */
}
```

And just like that, if any of those checks fail four times in a row the device will mark itself as non-genuine and throw up the `Error-A12` symptoms. I asked Claude to give this a look over and evidently there are actually 51 total spots that can set it but that's a problem for another day...

## Well What's In My OTP???

Now that I knew what the firmware was actually checking, using the UBoot shell to run commands was easier than compiling and moving across a binary to attempt and get the OTP bytes from Linux userspace.

Similar to the RE'd check for reading the OTP, these commands spit out my ER-12s OTP. These commands will differ depending on the SPI chip that is present due to different manufacturers or versions; my ER-12 has a `MX25L6405D` and the commands were confirmed with the [datasheet](https://www.macronix.com/Lists/Datasheet/Attachments/8575/MX25L3205D,%203V,%2032Mb,%20v1.5.pdf).

```
sspi 0 32 9f000000          # RDID - confirm ID
sspi 0 8  b1                # ENSO - enter OTP
sspi 0 256 03000000...      # READ - walk 64 bytes
sspi 0 8  c1                # EXSO - leave the window
sspi 0 32 9f000000          # RDID - confirm normal reads resumed
```

Reading out the OTP yields 28 bytes of data and then all `0xFF`s. Since we could see the check where the OTP is verified, I pulled out that blob from `mtdblock2` and checked it against my extracted OTP contents...

Welp, everything here seems to match fine. Seems that the problem resides elsewhere.

## All Error Codes

I asked Claude to just go ham and figure out all possible options.

While there are 51 failure sites, there are only 45 distinct flags causing some repeats. Each bit records what kind of check failed, not where the check occured. Several checks happen in more than one place such as `[3].0`. `[3].0` is a three-way branch on the board model; both of the non-passing arms (model 0x12 / "anything that isn't 0x07 or 0x12") will record the same flag because they mean the same thing. This means that a cleared bit narrows things down to a small group rather than always narrowing it down to a single check.

| Flag (Byte.Bit) | What failed | Function |
| --- | --- | --- |
| `[2].1` | post-kfree consistency check | `yoash4` |
| `[2].2` | post-kfree consistency check (0x40-byte buffer) | `yoash4` |
| `[2].3` | board/model ID at `mtdblock2+0xA000` not in the accepted set `{01,04,06-12}` | `oo5ein` |
| `[2].4` | live RDID JEDEC ID != the JEDEC ID stored at `mtdblock2+0xa02e` | `eet5De` |
| `[2].5` | the OTP comparison verdict | `eet5De` |
| `[2].6` | lookup in `/etc/board.info` returned nothing - key missing or file unreadable | `eet5De` |
| `[2].6` | lookup in `/etc/board.info` returned nothing - key missing or file unreadable | `eet5De` |
| `[2].7` | board/model ID byte at `mtdblock2+0xA000` did not validate | `eet5De` |
| `[2].7` | board/model ID byte at `mtdblock2+0xA000` did not validate | `eet5De` |
| `[3].0` | board model ID is `0x12` - this module build has no passing route for it | `eet5De` |
| `[3].0` | board model ID is neither `0x07` nor `0x12` - no passing route | `eet5De` |
| `[3].3` | `board.sysid` from `/etc/board.info` != the sysid word at `mtdblock2+0xa01e` | `eet5De` |
| `[4].5` | reference load asked for more than `0x10000` bytes | `eeMoos` |
| `[4].6` | short read from `/dev/mtdblock2` - fewer bytes than requested | `eeMoos` |
| `[4].7` | destination capacity smaller than the requested length | `eeMoos` |
| `[5].5` | called with a NULL destination buffer | `maesha` |
| `[5].6` | called with a NULL byte-count out-parameter | `maesha` |
| `[5].7` | called with a NULL path | `maesha` |
| `[6].0` | `filp_open()` returned NULL - file missing or unopenable | `maesha` |
| `[6].1` | `vfs_read()` returned 0 bytes from the opened file | `maesha` |
| `[7].7` | `simple_strtoul` on `board.sysid` left trailing junk (endptr not at NUL) | `eet5De` |
| `[8].0` | `simple_strtoul` on `board.cpurevision` left trailing junk | `eet5De` |
| `[8].3` | check on an `snprintf`-built string failed | `och0vi` |
| `[8].4` | check on an `snprintf`-built string failed | `och0vi` |
| `[8].5` | check on an `snprintf`-built string failed | `och0vi` |
| `[9].4` | check on a `/dev/mtdblock2` record field failed | `yoash4` |
| `[9].5` | check on a `/dev/mtdblock2` record field failed | `yoash4` |
| `[9].6` | check on a `/dev/mtdblock2` record field failed | `yoash4` |
| `[9].7` | check on a `/dev/mtdblock2` record field failed | `yoash4` |
| `[a].0` | board/model ID byte at `mtdblock2+0xA000` did not validate | `eet5De` |
| `[a].1` | board/model ID byte at `mtdblock2+0xA000` did not validate | `eet5De` |
| `[a].2` | board/model ID byte at `mtdblock2+0xA000` did not validate | `eet5De` |
| `[a].4` | `memcpy`'d buffer failed its follow-up check | `eet5De` |
| `[a].5` | post-kfree consistency check | `eet5De` |
| `[b].7` | CP0 PRId != the CPU ID stored at `mtdblock2+0xa0b3` | `eet5De` |
| `[c].3` | `board.cpurevision` from `/etc/board.info` != the value at `mtdblock2+0xa0b3` | `eet5De` |
| `[12].1` | reference load could not supply the expected OTP bytes | `eet5De` |
| `[12].3` | mirror check - word at `mtdblock2+0xa020` != word at `mtdblock2+0x0e` | `eet5De` |
| `[12].4` | mirror check - word at `mtdblock2+0xa01e` != word at `mtdblock2+0x0c` | `eet5De` |
| `[12].5` | post-kfree consistency check | `eet5De` |
| `[12].5` | post-kfree consistency check | `eet5De` |
| `[13].7` | check on a `/dev/mtdblock2` record field failed | `Maquio` |
| `[14].0` | check on a `/dev/mtdblock2` record field failed | `Maquio` |
| `[14].0` | check on a `/dev/mtdblock2` record field failed | `Maquio` |
| `[14].0` | check on a `/dev/mtdblock2` record field failed | `Maquio` |
| `[14].1` | a 32-bit field read from the `/dev/mtdblock2` record did not validate | `eet5De` |
| `[14].3` | check on a `0x40`-byte buffer failed | `joh7oo` |
| `[14].6` | `maesha` result did not validate | `och0vi` |
| `[14].7` | post-kfree consistency check | `eet5De` |
| `[15].5` | `strncasecmp` comparison did not match | `och0vi` |
| `[16].5` | `kmalloc_order()` returned NULL - scratch allocation failed | `bah4ie` |

![Painguin](./painguin.jpg)

## Why Three Kernel Modules

So checking all three modules with `nm` looking for the grouping of odd six character ASCII names yields that they all contain the same code. This distinction can be seen with the following:

```bash
nm ubnt_platform.ko tdts.ko mpls_fwdr.ko \
    | awk '$3 ~ /^[A-Za-z][A-Za-z0-9]{5}$/ {print $3}' \
    | sort | uniq -c | awk '$1 == 3 {print $2}' | paste -sd' '

# aeNieh aePh8A aexe5E Ahn4qu ahRie4 ahT9ie ahz7ph aicah8 aihena aijoog aithai
# an1Mie aoph6u aothoh asheiS au0eiM bae5xo Booyuh caiphe Chie5c EeheeB eej5ik
# eeMoos eeshah eet5De eic0up eitaic eonae8 geigie Hieyio huquoh ibaiBa iefieV
# Iey8oh Ithool kae0ei kae3oh kah4ei maesha Maquio me5Too Me6ohp Nu2aev oB6bee
# och0vi ohN5ai ohs7ae Ohz0Bo Onoota oo5ein oob2ph ooBees oot5La Ooth3x Ouloo4
# phahbo queepo reetah sae7ee sahvee shei4h shoong tieghe togai7 Uf3iep uHaequ
# Vohnga wah7ma wiedae Xepie5 xoesh7 yai2le yu0ziw zoYaeT
```

All three kernel modules share almost the exact same code which means that each should be able to mark the device with the `Error-A12` if a different module on the device is missing or falls through. This is why the earlier steps had to disable multiple modules for the device to reboot without the error appearing.

## TLDR

`Error-A12` is not a just flash error. It is Ubiquiti's generic tamper flag with 51 different triggers. Every trigger will produce an identical list of symptoms even if some of the checks have nothing to do with "genuine" devices.

Hopefully this helps you narrow down your `Error-A12` issue further. The proverbial do a TFTP recovery may fix some of the listed failures but others won't be fixed by just restoring the firmware. I never nailed down which of the 51 flags was actually mine leading to the 'partially' in the title... but a firmware upgrade to latest did seem to make it disappear on my unit.

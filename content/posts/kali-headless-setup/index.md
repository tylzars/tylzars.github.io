---
title: "Kali x86 VNC Headless Setup"
date: 2023-11-20T12:13:32+05:30
description: "Headless VNC Setup for Kali on Intel x86 Commands"
tags: [kali, system]
---

## Overview

I wanted to be able to use an old Intel NUC for a headless Kali instance. I came into a lot of problems with Kali's defualt TightVNCServer being a gray (grey?) screen and found the solution below to work perfectly. I enable autologin for headless operation to run my userspace application launching VNC but with the option to also SSH in assuming that doesn't work. This solution will make the defualt desktop on our fake display adapter available over VNC. The `-loop` flag will allow you to close and reconnect the VNC and many times as you want.

## Steps

1. Edit the lightdm config to setup autologin with: `sudo nano /etc/lightdm/lightdm.conf`
2. Update these two lines in the \[SeatDefualt\] config: autologin-user=username / autologin-user-timeout=0
3. Install x11vnc: `apt install x11vnc -y`
4. Run `vncserver` to setup password for VNC
5. Make a userspace autostart directory: `cd ~./config/ && mkdir autostart/`
6. Build .desktop file to run our VNC start command: `nano autostart/x11vnc.desktop` and add these lines:

```bash
[Desktop Entry]
Type=Application
Name=x11vnc
Exec=x11vnc -display :0 -autoport -localhost -bg -xkb -ncache -ncache_cr -quiet -forever -loop
Comment=Starts an x11vnc server on port kali:5900
RunHook=0
```

7. Enable SSH: `sudo systemctl enable ssh`
8. Reboot and profit!

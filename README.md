# Sony X90H (KD-55X9000H) root notes

![Sony X90H](media/x90h.jpg)

*by pearlxcore*

This is the write-up and the code from a project on a Sony X90H
(KD-55X9000H, BRAVIA VH1, firmware 626241, kernel `4.19.260-ab626241`).
I got root on the TV.

It is not a bootloader unlock or a persistent Magisk-style root. It is per
boot. A reboot removes it.

On the same TV and firmware it can be tried. Different firmware will probably
not work, because the addresses and the module CRCs are for this build.

## Contents

- [What it gives](#what-it-gives)
- [What it does not give](#what-it-does-not-give)
- [Workflow: from the surface to root](#workflow-from-the-surface-to-root)
  - [Stage 0: Surface](#stage-0-surface)
  - [Stage 1: Shell root](#stage-1-shell-root)
  - [Stage 2: Init domain](#stage-2-init-domain)
  - [Stage 3: Kernel module](#stage-3-kernel-module)
  - [Stage 4: Server](#stage-4-server)
  - [Stage 5: Bootloader attempt](#stage-5-bootloader-attempt)
- [Key technical details](#key-technical-details)
- [Requirements](#requirements)
- [Running it](#running-it)
- [Warnings](#warnings)
- [The bootloader unlock attempt](#the-bootloader-unlock-attempt)
- [If full root is achieved](#if-full-root-is-achieved)
- [FAQ](#faq)
- [Building](#building)
- [Author](#author)

## What it gives

- uid 0 in the `shell` domain, starting from an unprivileged `adb shell`
- a small kernel module that sets SELinux to permissive
- a command server running in the `init` domain, reading
  `/data/local/tests/x90cmd`

## What it does not give

- persistence across reboots
- a bootloader unlock
- a custom kernel or a patched system image

## Workflow: from the surface to root

The chain has five stages. Each stage starts from the result of the previous
one and produces the primitive that the next stage needs. The order matters:
without the shell root there is no fake cred for the property socket; without
the init domain there is no module load; without the module there is no
permissive SELinux; without permissive SELinux the server stays limited.

### Stage 0: Surface

The entry point is an unprivileged adb shell: uid 2000, gid 2000, domain
`u:r:shell:s0`. There is no root, no special capability and no writable block
device. The useful facts on this build are:

- `perf_event_paranoid` is -1, so an unprivileged process can open perf events
  and sample kernel IPs.
- The shell can create AF_NETLINK and AF_UNIX sockets.
- The shell can connect to the property service socket.

The reachable kernel surface at this stage is narrow: perf events, netlink,
unix sockets, binder and a few vendor character devices. The chain only uses
the first two. Everything else is either not exposed to the shell domain or
requires a capability that uid 2000 does not have.

This stage does not give root. It gives a restricted but real code execution
context from which a kernel bug can be reached. The bug used here is
CVE-2023-6931.

### Stage 1: Shell root

CVE-2023-6931 is an out-of-bounds increment in the perf group read. A perf
event group is opened with a leader that has `PERF_FORMAT_GROUP` and many
siblings. `perf_read` allocates `values[]` from the read size, while
`perf_read_group` walks `leader->nr_siblings` and does
`values[n] += perf_event_count(sub)` for every sibling. A group larger than
the allocation writes past the buffer.

The heap work is the fragile part. perf event objects come from a dedicated
cache, while netlink sockets are kmalloc-2k. The exploit creates a large batch
of netlink sockets, closes every 16th to leave holes, waits out the RCU grace
period that defers the real free, and then allocates a few more sockets to
drain the per-CPU freelist. The result is a hole slab whose next object is a
live netlink socket, and the perf `values[]` buffer is allocated into that
hole.

The exploit shapes the heap so the 2k `values[]` buffer sits next to a
netlink socket in kmalloc-2k. The overflow is aimed at the socket's
`sk_write_space` at `0x2a8`. The sibling counter is calibrated so the added
value is exactly `netlink_sock_destruct_work - sock_def_write_space`, which is
`0x76f58`. The field now points at the work function.

The calibration must be exact. If the counter is a few counts off, the
pointer lands inside the function instead of at its entry and the first
`setsockopt` panics. `calibrate_counter` reads the event back and trims the
count until it matches the delta.

A write to the socket (`setsockopt(SO_SNDBUF)`) calls `sk_write_space(sk)`.
Instead of waking a waiter, it runs `netlink_sock_destruct_work` with the
socket pointer. That function does
`container_of(work, struct netlink_sock, work)` with `work` at `0x440`, so it
treats the sprayed 2k buffer as a netlink socket. Its `sk_destruct` at `0x2c0`
points at `commit_creds`, and the "socket" is the fake cred.

The fake cred is a normal `struct cred` inside the sprayed buffer: usage
`0x40000000` so it is never freed, uid/euid 0, full capabilities, and
pointers to the real `root_user`, `init_user_ns` and `init_groups`.
`commit_creds` installs it.

The trigger frees an interior pointer (`kfree(X + 0x3c0)`). The next 2k
allocation is a repair send that lands exactly on the live cred and rewrites
it with a valid copy. Without that repair the live credential is left on a
freed object and the process dies on the next permission check.

Only the first poisoned socket runs the gadget. The trigger loop stops as soon
as uid or gid reads 0.

Result: uid 0, but still in `u:r:shell:s0`. SELinux still blocks block
devices, module loading and most privileged interfaces.

### Stage 2: Init domain

The next wall is SELinux, not the uid. The shell domain cannot `module_load`,
cannot mount a filesystem and cannot use most vendor interfaces. The chain
needs a domain with those permissions. `init` is the target: it can load
modules from `vendor_file` and mount images.

The bridge is the property service. A shell client connected to
`/dev/socket/property_service` has an `sk_security_struct`:

```
u32 sid;       // shell
u32 peer_sid;  // init
u16 sclass;
```

The client `sid` is shell. The `peer_sid` is init, because the server socket
was created by init. The whole object is 16 bytes.

`selinux_cred_prepare` copies 24 bytes from it, so the last 8 bytes come from
the neighbouring kmalloc-16 object and become `keycreate_sid` and
`sockcreate_sid`. That is why the payload avoids `O_CREAT` and socket creation
until those fields are patched.

`CONFIG_NETLABEL` is off, so SELinux's `cred_sid()` reads
`cred->security + 4`. For a `task_security_struct` that is `sid`; for an
`sk_security_struct` it is `peer_sid`. Pointing the fake cred at the socket's
security object therefore makes every permission check see init.

The trigger points at `sksec - 4`, so the first checks still see shell and the
trigger survives. The repair send then writes `fake2` with `security = sksec`
into the freed interior pointer, so the live cred now reads init.

`setresuid(0,0,0)` runs `prepare_creds()` and `selinux_cred_prepare()`, which
does a 24-byte `kmemdup` of the security object. That produces a real
`task_security_struct`:

```
osid        = shell
sid         = init
exec_sid    = 0
create_sid  = 0
keycreate_sid = 0
sockcreate_sid = 0
```

After `commit_creds`, the process is in `u:r:init:s0` with uid 0. From here,
`module_load` from `vendor_file`, `mount`, and the loop device are available.

The property socket must stay open. Its `sk_security_struct` is the object the
live credential points at. Closing the socket frees it and leaves the cred
dangling.

### Stage 3: Kernel module

`init` can `module_load` from `vendor_file`, has `CAP_SYS_MODULE`, and the
kernel has module signature checking off. That is the gap that turns a
userspace credential into kernel code execution.

The module is not a general kernel exploit. It is a two-byte write with the
runtime `selinux_state` address passed as two signed 32-bit parameters, so no
64-bit module parameter symbol is needed.

The module is built against the Sony `4.19.260-ab626241` source and config
because `CONFIG_MODVERSIONS` is on. The CRCs must match the TV kernel
(`module_layout 0x690d7734`, `param_ops_int 0xf5a2f68d`,
`_mcount 0x1fdc7df2`), and the `struct module` layout must match. A module
built against the wrong tree and only CRC-patched loads but hangs in
`ftrace_module_init`, because it reads `num_ftrace_callsites` at the Sony
offset from a differently shaped `__this_module`.

An 8 MiB ext4 image with 4 KiB blocks is created with `x90mod.ko` at the root.
The root inode and the file carry `u:object_r:vendor_file:s0`. The image is
copied to `/data/vendor/x90mod.img`, attached to loop0 with `LOOP_SET_FD` and
`LOOP_SET_BLOCK_SIZE 4096`, mounted read-only at `/data/x90mnt`, and loaded
with `finit_module`.

The image is copied to `/data/vendor` because the kernel loop worker can read
`vendor_data_file`, while the inner labels are `vendor_file`, which is what
`init` is allowed to load. Both halves matter.

The module takes the runtime `selinux_state` address as two signed 32-bit
parameters and writes two bytes:

```
p[0] = 0; // disabled
p[1] = 0; // enforcing
```

`enforcing = 0` makes SELinux permissive. `disabled = 0` keeps the labels
valid, so the system keeps working instead of turning every context into
`unlabeled`.

Result: permissive SELinux with kernel code execution. Every policy check is
still evaluated and logged, but not enforced.

### Stage 4: Server

The payload forks a server in the init domain. The server polls
`/data/local/tests/x90cmd` every 100 ms, runs `/system/bin/sh -c <cmd>`, and
writes the output to `/data/local/tests/x90log`.

The command runs through `/system/bin/sh -c`. The exec transition gives the
command a different label (`u:object_r:unlabeled:s0`), but permissive SELinux
does not care. The server process itself remains in the init domain.

The parent process stays parked. It holds the repaired credential and the skb
that backs it. Killing the parent or closing the inherited fds can trip the
`cgroup_sk_free` teardown panic.

The mailbox files are created before the transition, while the process is
still shell, so the init server inherits valid file descriptors and paths.

The server is per boot. A reboot removes it. Re-run the payload to restore it.

### Stage 5: Bootloader attempt

The U-Boot environment lives at offset 0 of `uboot_env_a`: 128 KiB, a CRC32
over the block, and a set of plaintext variables (`devicestate`, `bootcmd`,
`bootargs`). The bootloader reads it and does not rewrite it at boot.

Editing `devicestate=lock` to `unlock` makes the bootloader show
`unlocked`/`orange`. It skips the official unlock
provisioning (keybox/RPMB), so the Trusty keymaster hangs in `generate_key`,
setup and DRM break, the first boot takes over 4 hours, and returning to
`lock` causes a boot loop. The `keystore2` watchdog showed `generate_key`
pending 200 to 1,260 seconds; the setup wizard blocked on it and went black. Recovery is the hold-power-while-plugging factory
wipe. `veritymode` stays `enforcing`, so AVB bypass was never proved.

This stage is not part of the working chain. The env write is a real
boot-chain integrity weakness, but it is post-exploitation: root plus
permissive is needed to write the block device. Do not do it on a daily-use
TV.

## Key technical details

All addresses are link-time for `4.19.260-ab626241`. The runtime address is
the link-time address plus the KASLR slide.

```
commit_creds                0xffffff80080f3f44
selinux_socket_sendmsg      0xffffff8008438bf4
selinux_state               0xffffff80092a4478
root_user                   0xffffff800916a790
init_user_ns                0xffffff800916a5a0
init_groups                 0xffffff8009170920
netlink_proto               0xffffff800920fe88
```

Offsets used by the fake objects:

```
sk_filter          0x108
sk_wmem_alloc      0x144
sk_prot_creator    0x218
sk_write_space     0x2a8
sk_destruct        0x2c0
cred.security      0x78
cred.user          0x80
cred.user_ns       0x88
cred.group_info    0x90
netlink work       0x440
```

Module CRCs:

```
module_layout   0x690d7734
param_ops_int   0xf5a2f68d
_mcount         0x1fdc7df2
```

The perf overflow index is `TFD_WS = 340`, which lands at byte
`2048 + 0x2a8` in the neighbouring 2k object. The fake netlink object starts
at `2048 - 0x440 = 0x3c0` inside the sprayed buffer.

## Requirements

- Sony X90H (KD-55X9000H), BRAVIA VH1, firmware 626241, kernel
  `4.19.260-ab626241`.
- adb over the network:
  Settings -> Device Preferences -> About -> tap **Build** 7 times,
  then Developer options -> enable **Network debugging**.
- The files in this repo.

## Running it

1) Connect:

```
adb connect <tv-ip>:5555
```

2) Push the payload and the module image:

```
adb push prebuilt/prod_exploit_v21 /data/local/tmp/
adb push prebuilt/x90mod_sony.img /data/local/tests/x90mod.img
adb shell chmod 755 /data/local/tmp/prod_exploit_v21
```

3) Run it (it daemonizes itself):

```
adb shell "nohup /data/local/tmp/prod_exploit_v21 > /data/local/tmp/p21.log 2>&1 < /dev/null &"
```

4) Wait 2 to 3 minutes. Then check:

```
adb shell getenforce
adb shell tail -5 /data/local/tests/x90log
```

Expected: **Permissive** and **X90INIT READY**.

5) Send it a command:

```
adb shell "echo 'id; getenforce' > /data/local/tests/x90cmd.tmp; mv /data/local/tests/x90cmd.tmp /data/local/tests/x90cmd"
adb shell cat /data/local/tests/x90log
```

## Warnings

- **Per boot.** A reboot removes it.
- **Don't kill the exploit parent** or close its fds. There is a
  `cgroup_sk_free` panic waiting there.
- **Don't flip `devicestate` in the U-Boot env.** It shows `orange`, breaks
  the TEE/keystore, wipes data, and can boot-loop. See the bootloader unlock
  section below.
- If it panics or boot-loops: **unplug the TV, hold the power button on the
  TV, plug it back in, keep holding**. Expected: an "erasing" screen, then
  setup. This is the recovery that worked for me.

## The bootloader unlock attempt

The internal name for this stage was S11. It was an attempt to unlock the
bootloader by editing the plaintext U-Boot environment.

The TV stores its boot config in a plaintext U-Boot environment on
`uboot_env_a` (128 KiB, CRC32, no signature). One of the variables is:

```
devicestate=lock
```

I changed it to `unlock`, fixed the CRC, wrote it back. The bootloader
accepted it and returned:

```
ro.boot.vbmeta.device_state = unlocked
ro.boot.verifiedbootstate   = orange
```

But it skipped the official unlock provisioning (keybox/RPMB). The Trusty
keymaster then hung in `generate_key` (pending 200 to 1,260 seconds), the
setup wizard black-screened and froze, and accounts/DRM/attestation were
broken. The first boot took over 4 hours on the Android boot animation.

Going back to `devicestate=lock` caused a boot loop at the Sony logo. The
locked boot could not mount `/data` that had been re-provisioned under the
unlocked state.

Recovery: unplug the TV, hold the power button on the TV, plug it back in,
keep holding. The TV shows "erasing", wipes `/data`, reboots, and reaches
setup. After that the bootloader showed `locked`/`green` again and keystore
was healthy.

`veritymode` stayed `enforcing` throughout, so an AVB bypass was never proved.
Do not do this on a daily-use TV.

## If full root is achieved

The chain in this repo stops at a per-boot root. A full root, meaning a
persistent unlock or a modified boot/vendor image, would add the following.

**Persistence.** Root would survive reboots. A module, init hook or patched
service could load at boot without re-running the exploit. OTA updates would
need to be controlled or blocked.

**Firmware control.** With AVB and dm-verity out of the way, the boot image,
vendor and system partitions could be modified. That allows a custom kernel,
modules loaded at boot, a different SELinux policy and removal of vendor
restrictions.

**Sony X1 and PQ research.** The picture pipeline becomes inspectable at the
data level:

- dump and compare the `recipe_a` and `recipe_b` partitions, which hold the PQ
  parameter store;
- instrument `sony_pqctrl`, the MediaTek PQ HAL and the display driver;
- read the panel calibration, local dimming and luminance limiter parameters;
- trace how picture modes, tone mapping and motion settings map to registers
  and tables;
- use the service menu pages for EDID, HDMI terminal variations and PQ
  customization as a map of what the X1 exposes.

**HDMI 2.1 research.** With root and a custom kernel, the HDMI receiver can be
examined directly:

- read the EDID banks the TV advertises and compare them with the actual
  receiver capabilities;
- inspect FRL link training, lane configuration and error counters;
- check what 4K120 actually does, full resolution or vertical subsampling, and
  whether a different pixel format avoids it;
- inspect VRR, ALLM, eARC and DSC negotiation;
- test modified EDID or terminal settings on a recoverable unit.

**Kernel and driver work.** A custom kernel with KASAN, ftrace, kprobes and
debugfs would allow proper fuzzing of the vendor drivers, including
`dtv_driver`, `sony_pqctrl` and the HDMI path.

**What it does not fix.** DRM and attestation. An unlocked bootloader without
the official provisioning breaks the Trusty keymaster and RPMB state, which is
what happened in the bootloader attempt. Widevine, Play Integrity and some
streaming apps would be degraded or broken. A proper unlock would need the
official provisioning flow, which this TV does not expose.

**Practical note.** The runtime root in this repo already allows much of the
PQ and HDMI inspection. Full root mainly adds persistence and the ability to
modify boot-loaded images.

## FAQ

**Does it survive a reboot?**
No. Per boot. A reboot removes it.

**Will it work on another model or firmware?**
No. The addresses, offsets and module CRCs are for this build.

**Does it unlock the bootloader?**
No. The env `devicestate` trick shows `orange` but breaks the TEE and wipes
data. Avoid it.

**Does it modify the firmware?**
No. It writes files under `/data` and loads a module into RAM. Nothing on the
system/vendor/boot partitions is changed.

**Is root required?**
An adb shell (uid 2000) is the entry point. No root needed to start.

**Can it be used on someone else's TV?**
No. Only devices owned or explicitly authorised to test.

**Is it legal?**
Depends on the jurisdiction. It is security research on owned hardware; check
local laws.

## Building

Exploit:

```
aarch64-linux-gnu-gcc -static -O2 -o prod_exploit_v21 prod_exploit_v21.c
```

The comment block at the top of the source is stale; the constants are the
production Sony ones.

Module: build against the Sony `4.19.260-ab626241` tree with
`CONFIG_MODVERSIONS`:

```
make -C <sony-tree> M=$PWD ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules
```

The CRCs used are in `module/sony-Module.symvers`. The ext4 image is 8 MiB,
4 KiB blocks, the `.ko` at the root, and `u:object_r:vendor_file:s0` on both
the root inode and the module file.

## Author

pearlxcore. Built on top of the public CVE-2023-6931 research and the Sony GPL
kernel source. The module only writes two bytes.

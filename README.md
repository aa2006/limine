# Limine

## Quick note
This fork of limine is taken from the [flat-os](https://github.com/flat-os/limine) which in turn is taken form [limine](https://github.com/limine-bootloader/limine).  
FlatOS adds support for the FlatFS which is used in MandelbrotOS.

### What is Limine?

Limine is an advanced x86/x86_64 BIOS/UEFI Bootloader which supports *modern* PC features
such as Long Mode, 5-level paging, and SMP (multicore), to name a few.

### Limine's boot menu

![Reference screenshot](/screenshot.png?raw=true "Reference screenshot")

[Photo by Nishant Aneja from Pexels](https://www.pexels.com/photo/close-up-photo-of-waterdrops-on-glass-2527248/)

### Supported boot protocols
* Linux
* stivale and stivale2 (Limine's native boot protocols, see STIVALE{,2}.md for details)
* Chainloading

### Supported filesystems
* ext2/3/4
* echfs
* FlatFS
* FAT16/32
* ISO9660 (CDs/DVDs)

### Supported partitioning schemes
* MBR
* GPT
* Unpartitioned media

## Binary releases

For convenience, for point releases, binaries are distributed. These binaries are
shipped in the `-binary` branches and tags of this repository (see [branches](https://github.com/limine-bootloader/limine/branches/all) and [tags](https://github.com/limine-bootloader/limine/tags)).

For example, to clone the latest binary release of the `v2.0` branch one can do
```bash
git clone https://github.com/MandelbrotOS/limine.git --branch=v2.0-branch-binary --depth=1
```
or, to clone a specific binary point release (for example v2.0.1)
```bash
git clone https://github.com/MandelbrotOS/limine.git --branch=v2.0.1-binary --depth=1
```

`limine-install` binaries are provided for Linux and Windows. In case one wants to
rebuild `limine-install`, simply use `make` in the binary release.

## Building the bootloader

*These steps are not necessary if cloning a binary release. if so, skip to the*
*next paragraph.*

It is necessary to first build the set of tools that the bootloader needs
in order to be built.

This can be accomplished by running:
```bash
make toolchain
```
*The above step may take a while*

After that is done, the bootloader itself can be built with:
```bash
make
```

The generated bootloader files are going to be in `bin`.

## Installing Limine binaries

This step is optional as the bootloader binaries can be used from the `bin` or
release directory just fine. This step will only install them in a `share` and `bin`
directories in the specified `PREFIX` (default is `/usr/local`).

Use `make install` to install Limine binaries, optionally specifying a prefix with a
`PREFIX=...` option.

## How to use

### UEFI
The `BOOTX64.EFI` file is a vaild EFI application that can be simply copied to the
`/EFI/BOOT` directory of a FAT32 formatted EFI system partition. This file can be
installed there and coexist with a BIOS installation of Limine (see below) so that
the disk will be bootable by both BIOS and UEFI.

The boot device must to contain the `limine.cfg` file in
either the root or the `boot` directory of one of the partitions, formatted
with a supported file system (the ESP partition is recommended).

### BIOS/MBR
In order to install Limine on a MBR device (which can just be a raw image file),
run `limine-install` as such:

```bash
limine-install <path to device/image>
```

The boot device must to contain the `limine.sys` and `limine.cfg` files in
either the root or the `boot` directory of one of the partitions, formatted
with a supported file system.

### BIOS/GPT
If using a GPT formatted device, there are 2 options one can follow for installation:
* Specifying a dedicated stage 2 partition.
* Letting `limine-install` attempt to embed stage 2 within GPT structures.

In case one wants to specify a stage 2 partition, create a partition on the GPT
device of at least 32KiB in size, and pass the 1-based number of the partition
to `limine-install` as a second argument; such as:

```bash
limine-install <path to device/image> <1-based stage 2 partition number>
```

In case one wants to let `limine-install` embed stage 2 within GPT's structures,
simply omit the partition number, and invoke `limine-install` the same as one would
do for an MBR partitioned device.

The boot device must to contain the `limine.sys` and `limine.cfg` files in
either the root or the `boot` directory of one of the partitions, formatted
with a supported file system.

### BIOS CD-ROM ISO creation
In order to create a bootable ISO with Limine, place the `limine-cd.bin`,
`limine.sys`, and `limine.cfg` files into a directory which will serve as the root
of the created ISO.
(`limine.sys` and `limine.cfg` must either be in the root or inside a `boot`
subdirectory; `limine-cd.bin` can reside anywhere).

Place any other file you want to be on the final ISO in said directory, then run:
```
genisoimage -no-emul-boot -b <relative path of limine-cd.bin> \
            -boot-load-size 4 -boot-info-table -o myiso.iso <root directory>
```

*Note: `genisoimage` is usually part of the `cdrtools` package.*

`<relative path of limine-cd.bin>` is the relative path of `limine-cd.bin` inside
the root directory.
For example, if it was copied in `<root directory>/boot/limine-cd.bin`, it would be
`boot/limine-cd.bin`.

### BIOS/PXE boot
The `limine-pxe.bin` binary is a valid PXE boot image.
In order to boot Limine from PXE it is necessary to setup a DHCP server with
support for PXE booting. This can either be accomplished using a single DHCP server
or your existing DHCP server and a proxy DHCP server such as dnsmasq.

`limine.cfg` and `limine.sys` are expected to be on the server used for boot.

### Configuration
The `limine.cfg` file contains Limine's configuration.

An example `limine.cfg` file can be found in `test/limine.cfg`.

More info on the format of `limine.cfg` can be found in `CONFIG.md`.

### Example
For example, to create an empty image file of 64MiB in size, 1 echfs partition
on the image spanning the whole device, format it, copy the relevant files over,
and install Limine, one can do:

```bash
dd if=/dev/zero bs=1M count=0 seek=64 of=test.img
parted -s test.img mklabel msdos
parted -s test.img mkpart primary 1 100%
parted -s test.img set 1 boot on # Workaround for buggy BIOSes

echfs-utils -m -p0 test.img quick-format 32768
echfs-utils -m -p0 test.img import path/to/limine.sys limine.sys
echfs-utils -m -p0 test.img import path/to/limine.cfg limine.cfg
echfs-utils -m -p0 test.img import path/to/kernel.elf kernel.elf
echfs-utils -m -p0 test.img import <path to file> <path in image>
...
limine-install test.img
```

One can get `echfs-utils` by installing https://github.com/echfs/echfs.

## Acknowledgments
Limine uses a stripped-down version of [tinf](https://github.com/jibsen/tinf).

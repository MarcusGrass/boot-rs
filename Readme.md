# Boot-rs
A collection of tools to create an ergonomic and secure
encrypted boot-process.

## Considerations
How do you make sure that when your kernel boots that it hasn't been 
compromised?  

An answer to that question could be to have it encrypted, if the bootloader 
can encrypt and then launch into it, then it hasn't been compromised. As 
long as the kernel that boots is actually your kernel, and not a replacement.  

That brings the question to whether the bootloader can be trusted, it can't.  
You can use secure-boot to make sure that it's indeed your bootloaded that runs.  
Another solution is to embed your disk-decryption keys in the initramfs of your 
encrypted kernel.  
This way you know it's indeed your kernel that is running, since it knows how 
to decrypt your disks.  
Something that's problematic about that is that a malicious bootloader could 
for example record your decryption key, use it to decrypt your kernel, 
get your disk decryption keys from the initramfs, launch a malicious kernel, 
and decrypt your disks with the stolen keys.  So secure boot is likely 
the best way to go.

## Functionality
This project's overall functionality.  

### Boot-pre-os
This project contains a bootloader which can decrypt the kernel after 
generating configuration using the cli `boot-strap` which is compiled into the bootloader.  
The bootloader can then be signed, again using `boot-strap`, if that certificate is added, and 
secure boot enabled. The very early boot process should be safe.  

### Os-boot
The bootloader decrypts the kernel and launches the image.  
The initramfs, which can be generated by `boot-strap`, then takes over 
and decrypts your disks using the keys saved in the initramfs.  
The initramfs is loaded into ram by the kernel, and removed after the early-os-boot process, 
when control is handed over to `/sbin/init`. After load and before removal, the keys reside in RAM and 
are vulnerable to low-level attacks.  

## Setup
There are a few steps required to set up `boot-rs`.  

### Generate initramfs
The initramfs can be generated by `boot-strap initramfs -i initramfs.cfg -d initramfs`.  
This will generate an initramfs directory with the appropriate files to unlock a cryptodisk.  

Test by running `cryptsetup luksOpen --key-file initramfs/crypt.key --test-passphrase <cryptodisk>`.  

To get `initramfs-rs` as the init executable, compile it by `./build_init -r` then copy it to the initramfs directory as `init`. 
Ex: `cp target/release/initramfs-rs /root/initramfs/init`.  

### Build kernel
Build the kernel as usual, but with modules built-in, and with the above generated initramfs built in.  

### Encrypt kernel
The kernel can then be encrypted using ex:
`boot-strap boot -i /usr/src/linux/arch/x86/boot/bzImage -k /boot/EFI/gentoo/gentoo-6.1.19.enc -c boot.cfg 
-d "HD(1,GPT,f0054eea-adf8-4956-958f-12e353cac4c8,0x800,0x100000)" -p /EFI/gentoo/gentoo-6.1.19.enc`.  
This will move the encrypted kernel into `/boot/EFI/gentoo/gentoo-6.1.19.enc`.

### Build bootloader
Encrypting the kernel generates a configuration file.  
Build `boot-rs` with that file included:

`./build-boot --profile lto`

### Sign the bootloader
Sign the bootloader using any preferred method, and/or copy it directly onto the boot disk ex:
`cp target/x86_64-unknown-uefi/lto/boot-rs.efi /boot/EFI/boot-rs.efi`.  

### Add a boot entry if one does not already exist
`efibootmgr -c -L "Boot-rs" -l "\EFI\boot-rs.efi" -d /dev/sda1`

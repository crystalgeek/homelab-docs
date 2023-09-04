![ntfy logo](./images/ntfy.png "ping ntfy!")

# ntfy install on Debian Linux

This is a quick and easy guide to get an ntfy server running and ready to forward push notifications to an Android and iOS device.

#### Software and hardware specification for this build:

* Hostname: LAB-UXA0001
* Operating System: Debian GNU/Linux 12.1 (bullseye)
* RAM: 1GiB
* Storage: x1 VHDX @ 5GiB
* Network: Hyper-V Network Adapter using DHCP
* Hyper-V Switch: External
* DVD Drive for ISO
* Bootloader: GRUB
* Extra packages in build:
    * sudo
    * curl

## Installation of the ntfy server service:

1. Download and install the latest .deb file from the [GitHub repository](https://github.com/binwiederhier/ntfy/releases/tag/v2.7.0): 
```bash
$ curl -L --output ~/ntfy_2.7.0_linux_amd64.deb https://github.com/binwiederhier/ntfy/releases/download/v2.7.0/ntfy_2.7.0_linux_amd64.deb
$ sudo dpkg -i ~/ntfy_*.deb
```

2. Start the service and enable at boot:

```bash
$sudo systemctl enable ntfy --now
```


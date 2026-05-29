# Proxmox USB Passthrough for WireDown ESP32 Auto-Flashing

**WARNING:** Unprivileged LXCs are finicky with USB passthrough. Permissions get messy. It is highly recommended to deploy WireDown on a **VM** or a **Privileged LXC** if you plan to use the auto-flash feature from the dashboard.

## 1. Identify the ESP32 USB Device

First, plug the ESP32 into your Proxmox host. Open the Proxmox host shell and run:

```bash
lsusb
```

Look for a device with `CP210x`, `CH340`, or similar UART-to-USB bridge. Note the vendor and product ID, e.g., `10c4:ea60`.

## 2. VM Passthrough (QEMU)

If running WireDown in a VM, passthrough is straightforward.

Find your VM ID, then run:

```bash
qm set <vmid> -usb0 host=10c4:ea60
```
(Replace `10c4:ea60` with your vendor:product ID).

Reboot the VM. The device should appear as `/dev/ttyUSB0` or `/dev/ttyACM0`.

## 3. LXC Passthrough (Privileged)

If running a Privileged LXC container, you need to allow the character device and mount it.

Find the major/minor numbers for the USB serial device on the Proxmox host:

```bash
ls -l /dev/ttyUSB0
```
Output looks like: `crw-rw---- 1 root dialout 188, 0 Oct 26 10:00 /dev/ttyUSB0`
(Here, major is 188, minor is 0).

Edit the LXC config file (e.g., `/etc/pve/lxc/101.conf`) and add:

```text
lxc.cdev.allow: c 188:* rwm
lxc.mount.entry: /dev/ttyUSB0 dev/ttyUSB0 none bind,optional,create=file
```

Restart the LXC container.

## 4. LXC Passthrough (Unprivileged)

Unprivileged containers remount root to an unprivileged user, causing permission denied errors on `/dev/ttyUSB0`. You have to mess with `lxc.idmap` to map the `dialout` group into the container.

This is tedious and breaks easily. Save yourself the headache and use a VM or privileged container.

## 5. Verify Inside the Guest

Log into your VM or LXC and check if the device exists and has the correct permissions:

```bash
ls -la /dev/ttyUSB0
dmesg | grep tty
```

You should see `/dev/ttyUSB0` owned by `root` and group `dialout`. The user running the backend (e.g., `root` or `docker` user) must have read/write access.

## 6. Install arduino-cli

To flash the ESP32, the guest needs `arduino-cli`. Run the provided setup script inside your WireDown instance:

```bash
cd /opt/wiredown/scripts
bash install_arduino_cli.sh
```

You are now ready to flash the ESP32 directly from the WireDown web UI.

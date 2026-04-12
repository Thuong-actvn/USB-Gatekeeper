# USB Gatekeeper

A USB access control tool for Linux. It uses a **Netlink socket** to communicate between a kernel module (which intercepts USB events) and a user-space daemon (which prompts the user for authorization).

## Prerequisites

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) gcc make
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Thuong-actvn/USB-Gatekeeper.git
   cd USB-Gatekeeper
   ```

2. **Build the project:**

   ```bash
   # Build module
   cd module
   make

   # Build user app
   cd ../user
   make
   ```

## Usage

1. **Load the Kernel Module:**
   ```bash
   cd module
   sudo insmod gatekeeper_mod.ko
   ```

2. **Run the User Daemon:**
   ```bash
   cd ../user
   sudo ./gatekeeper_user
   ```
   *USB-Gatekeeper ready*

## Background Service (Optional)

To run the daemon automatically in the background using systemd:

1. Edit `user/usb-gatekeeper.service`: Update `ExecStart=/path/to/user_app` with the absolute path to your `gatekeeper_user` executable.
2. Install and start the service:
   ```bash
   sudo cp user/usb-gatekeeper.service /etc/systemd/system/
   sudo systemctl daemon-reload
   # Start now
   sudo systemctl start usb-gatekeeper
   # Enable on boot (optional)
   sudo systemctl enable usb-gatekeeper
   ```
3. **Stop the service:**
   ```bash
   # Stop
   sudo systemctl stop usb-gatekeeper
   # Disable on boot (optional)
   sudo systemctl disable usb-gatekeeper
   ```
## Uninstall / Cleanup

```bash
# Unload kernel module
sudo rmmod gatekeeper_mod

# Cleanup build files
cd module && make clean
cd ../user && make clean
```

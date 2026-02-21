import subprocess
import requests
import os
import time

SOCKET_PATH = "/tmp/firecracker.socket"

# Remove old socket
if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

# Start firecracker process
fc = subprocess.Popen([
    "firecracker",
    "--api-sock", SOCKET_PATH
])

time.sleep(0.5)

session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

# set kernel
session.put(
    f"http+unix://{SOCKET_PATH.replace('/', '%2F')}/boot-source",
    json={
        "kernel_image_path": "./vmlinux",
        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
    }
)

# set rootfs
session.put(
    f"http+unix://{SOCKET_PATH.replace('/', '%2F')}/drives/rootfs",
    json={
        "drive_id": "rootfs",
        "path_on_host": "./rootfs.ext4",
        "is_root_device": True,
        "is_read_only": False
    }
)

# set machine config
session.put(
    f"http+unix://{SOCKET_PATH.replace('/', '%2F')}/machine-config",
    json={
        "vcpu_count": 1,
        "mem_size_mib": 256,
        "ht_enabled": False
    }
)

# start instance
session.put(
    f"http+unix://{SOCKET_PATH.replace('/', '%2F')}/actions",
    json={"action_type": "InstanceStart"}
)

# invoke function
subprocess.run([
    "ssh",
    "root@vm_ip",
    "echo '{\"x\": 5}' | python3 /usr/local/bin/check_virustotal.py"
])

# capture output
fc = subprocess.Popen(
    ["firecracker", "--api-sock", SOCKET_PATH],
    stdout=open("vm.log", "w"),
    stderr=subprocess.STDOUT
)

# clean shutdown
fc.terminate()
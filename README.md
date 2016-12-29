Purifier
===========
Purifier is a fast transparent stateful firewall powered by DPDK. It was created to solve transport layer DDoS attacks.

Installation
------------
- [Get DPDK 16.07](http://fast.dpdk.org/rel/dpdk-16.07.tar.xz)

- [Install DPDK](http://dpdk.org/doc/quick-start) 

- Reserve huge pages memory
```bash
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
```
- Load Modules to Enable Userspace IO
```bash
sudo modprobe uio
sudo insmod kmod/igb_uio.ko
```
- Define DPDK environment variable
set path to DPDK 
```bash
export RTE_SDK=/path/to/rte_sdk
```
- set target (In most cases it will be x86_64-native-linuxapp-gcc)
```bash
export RTE_TARGET=x86_64-native-linuxapp-gcc
```
- Compile the application
```bash
cd ../src
make
```
Runing app
----------
- [Bind NIC ports to igb_uio driver](http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-kernel-modules)

For example to bind eth1 and eth2 from the current driver and move to use igb_uio
```bash
./tools/dpdk_nic_bind.py --bind=igb_uio eth1
./tools/dpdk_nic_bind.py --bind=igb_uio eth2
```
Run the app
```bash
./build/purifier -c 0x7 -n 4
```

Autostarting using systemd
--------------------------
To start purifier as a daemon keeping the possibility of using its configuration console, [tmux](https://github.com/tmux/tmux) + systemd usage is proposed at the moment until the full-featured telnet/ssh console is implemented.

Systemd unit files examples:

- igb_uio module insertion unit `/etc/systemd/system/igb_uio_module.service`
```
[Unit]
Description=igb_uio module insertion

[Service]
Type=one-shot
RemainAfterExit=yes
# change that path for the one appropriate for you. Also keep in mind that Exec
# paths must be absolute
ExecStart=/sbin/insmod /opt/dpdk-16.07/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
ExecStop=/sbin/rmmod igb_uio

[Install]
WantedBy=multi-user.target

```

- DPDK device binding unit `/etc/systemd/system/dpdk-devbind.service`:
```
[Unit]
Description=DPDK device binding
After=igb_uio_module.service # the binding routing must start after loading the igb_uio module

[Service]
Type=one-shot
RemainAfterExit=yes
# Change the path and the NIC names to an appropriate ones.
ExecStart=/opt/dpdk-16.07/tools/dpdk-devbind.py -b igb_uio eth1 eth2
# When stopping the service, bring the NICs back to the linux network stack.
# NIC PCI addresses can be obtained from /opt/dpdk-16.07/tools/dpdk-devbind.py -s
# command output
ExecStop=/opt/dpdk-16.07/tools/dpdk-devbind.py -b ixgbe 0000:01:00.0 0000:01:00.1

[Install]
WantedBy=multi-user.target
```

- Actually the purifier run in tmux session `/etc/systemd/system/purifier.service`:
```
[Unit]
Description=Purifier firewall
After=igb_uio_module.service dpdk-devbind.service # staring only after all other preparations (module loading, NIC binding) have been made.

[Service]
Type=forking # Unfortunately, there is no way for running tmux without forking in systemd because it doesn't provide terminal to tmux
ExecStart=/usr/bin/tmux new-session -d -s purifier '/opt/purifier/src/build/purifier -c 0x7 -n 4'
Restart=always # if purifier crashes, systemd restarts it

[Install]
WantedBy=multi-user.target
```

Making all the service being autostarted:
```
systemctl enable igb_uio_module.service
systemctl enable dpdk-devbind.service
systemctl enable purifier.service
```

Staring them:
```
systemctl start igb_uio_module.service
systemctl start dpdk-devbind.service
systemctl start purifier.service
```

Check the status using command `systemd status <service name>`.

Now the purifier console should be available by entering root user's tmux session:
```bash
sudo tmux a
```

To send the console session background use `Ctrl-b d` keystroke (tmux default).

Constraints
-----------

- Tested with ixgbe NIC's

TODO
----

- Add mbuf extension
- Add ip defragmentation
- Add telnet/ssh support
- Rework lookup with SSE/AVX
- Add new white/black lists based on bitmaps 


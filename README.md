# cacdrive
harddrive emulator using cloudatcost's "cloud storage" as a storage backend.

# warning
it is *NOT* well tested, don't store anything unbackuped-&-importat with it, it could crash/corrupt your data at any time. (but if it actually does this, i would appreciate it if you could post a console crash log and sourcec revision at https://github.com/divinity76/cacdrive/issues/new )

also, unless the last line in the terminal is something like `upload queue emptied`, it is probably the wrong time to terminate cacdrive.. it uses an internal io cache for uploads (because the uploads are too slow for the kernel, so the kernel will terminate the IPC socket with a timeout error if i don't do an io upload cache and *lie* to the kernel about the write being complete. :( wasn't my first choice. )

# getting started

here's how to get started, using a debian-based distro (Debian/Ubuntu/Proxmox/Devuan/whatever)
(personally tested on debian 10 buster and ubuntu 18.04)
```sh
sudo apt install g++ git libcurl4-openssl-dev nano

sudo modprobe nbd
<modprobe should NOT give any output. if it does, that is probably an error.>

git clone --depth 1 https://github.com/divinity76/cacdrive.git

cd cacdrive

g++ src/main.cpp -std=c++17 -lcurl -lpthread -O2

cp config.conf.dist config.conf

nano config.conf
<insert username and password in config.conf>

dd if=/dev/zero of=sectorindex.sec bs=25 count=10000

sudo ./a.out config.conf api-tests
<make sure this does not crash horribly or something>

sudo ./a.out config.conf
<now wait for all worker threads to get ready, then open another terminal, if you have a GUI, use gparted, otherwise>

sudo dd if=/dev/zero of=/dev/nbd1

sudo time sync
<this is just testing, it should say "out of disk space" rather quickly if everything is working correctly.>

sudo mkfs.ext4 /dev/nbd1
<you can replace ext4 with whatever filesystem you want. for example, if you want a compressing filesystem (which might be a good  idea), you can use mkfs.btrfs instead of mkfs.ext4>

mkdir mountpoint

sudo mount /dev/nbd1 mountpoint
<or if you used mkfs.btrfs instead, try `sudo mount /dev/nbd1 mountpoint -o compress=zlib` >
```
- now the mountpoint folder should be cacdrive! :) 

# sector index file
the "sector index file" can be created with the command:
`dd if=/dev/zero of=sectorindex.sec bs=25 count=10000`, 
where 10000 is the number of sectors you want. each sector is 4096 bytes of cloud storage, but note that due to the `async delete old blocks *eventually*`-design, you should not allocate all your cloud storage to the drive, it could use more than you assign to it. 10 megabytes reserved space should probably suffice. (OTOH, because sectors containing only zeroes are never uploaded in the first place, the drive can also use significantly less space than allocated to it..)



# configuration
you can find an example configuration [here](https://github.com/divinity76/cacdrive/blob/master/config.conf.dist) - that said, 
the config file is line based, 1st line must be `format=1`, 2nd line is ignored (but must exist), line 3 contains the username (usually/always? an email), line 4 contains the password, line 5 contains the number of worker threads you want (higher count should increase IO speed, and it does not depend on how many CPU cores you have.. but try a low number first time around), line 6 contains the path to the sector index file, line 7 contains the nbd device to use (/dev/nbdX), and line 8 should not exist. a username or password or filepath containing newlines is not supported.



# ???
by the way, cacdrive is not assosiated with nor endorsed by C@C the company/staff in any way (afaik)

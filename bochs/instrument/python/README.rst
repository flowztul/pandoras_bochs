Pandora's Bochs
===============

Building
--------

Some build requisits on debian:
* python-dev
* libc6-dev
* libpq-dev

For compiling Pandora's Bochs on a Linux system (I didn't test it on Windows
yet), you'll have to configure it first. To compile a non-instrumented version
of Bochs, you can use the following command line:

::
    ./configure  --enable-all-optimizations

For configuring the instrumented version, use:

::
    ./configure --enable-all-optimizations --with-python --with-postgresql \
                --enable-instrumentation=instrument/python

Then use "make" to build it.

Disk Images
-----------

There are two alternatives for creating disk images for Bochs to use, convert an
existing VM image, or create new image and install Windows on it.

Converting Existing Images
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following instructions show how to convert VirtualBox VM images for using
them with Bochs, based on the VM images provided by Microsoft for Internet
Explorer compatibility testing, available at http://modern.ie/.

To experiment with that, go to the website and download the Windows XP VM with
Internet Explorer 8. You will end up with a RAR archive consisting of one or 
two files. Unrar it, and you should get a file named "IE8 - WinXP.ova", which
is an exported VirtualBox VM in TAR format, which can be extracted by running

::
$ tar xf 'IE8 - WinXP.ova'

This should yield a virtual machine configuration and a virtual disk image in
VMDK format named "IE8 - WinXP-disk1.vmdk". This first needs to be converted to
raw format. Unfortunately, the disk image has a virtual size of 128 GB, and
the VirtualBox conversion tool needs at least that much free disk space to
convert it. While the tool qemu-img from QEMU can also be used to convert VMDK
disk images, it cannot currently handle the file format version used here.
Therefore, the disk image needs to be converted to VDI format first, using
VBoxManage as follows:

::
    $ VBoxManage clonehd -format VDI 'IE8 - WinXP-disk1.vmdk' winxp.vdi
    0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
    Clone hard disk created in format 'VDI'. UUID: 6fcac4ce-7b94-4858-bf0d-87a4203921e0

Next, qemu-img can be used to convert that image to raw format, creating a 
sparse file that requires about 2 GB on disk:

::
    $ qemu-img convert -O raw winxp.vdi winxp.raw

    $ du -sh *
    1.1G	IE8 - WinXP-disk1.vmdk
    2.0G	winxp.vdi
    1.9G	winxp.raw

Unfortunately, Bochs apparently cannot handle disks that are as large as 128 GB.
Therefore, the filesystem and partition sizes must also be altered, using the
following steps, for example:

Add loopback devices for all partitions:

::
    $ sudo kpartx  -a winxp.raw 
    $ lsblk 
    NAME                      MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINT
    [...]
    loop0                       7:0    0 126.9G  0 loop  
    └─loop0p1 (dm-3)          254:3    0 126.9G  0 part  

Resize the NTS partition:

::
    $ ntfsresize --size 8388075520 /dev/mapper/loop0p1 
    ntfsresize v2013.1.13AR.1 (libntfs-3g)
    Device name        : /dev/mapper/loop0p1
    NTFS volume version: 3.1
    Cluster size       : 4096 bytes
    Current volume size: 136251728384 bytes (136252 MB)
    Current device size: 136251730944 bytes (136252 MB)
    New volume size    : 8388071936 bytes (8389 MB)
    Checking filesystem consistency ...
    100.00 percent completed
    Accounting clusters ...
    Space in use       : 2810 MB (2.1%)
    Collecting resizing constraints ...
    Needed relocations : 3 (1 MB)
    WARNING: Every sanity check passed and only the dangerous operations left.
    Make sure that important data has been backed up! Power outage or computer
    crash may result major data loss!
    Are you sure you want to proceed (y/[n])? y
    Schedule chkdsk for NTFS consistency check at Windows boot time ...
    Resetting $LogFile ... (this might take a while)
    Relocating needed data ...
    100.00 percent completed
    Updating $BadClust file ...
    Updating $Bitmap file ...
    Updating Boot record ...
    Syncing device ...
    Successfully resized NTFS on device '/dev/mapper/loop0p1'.
    You can go on to shrink the device for example with Linux fdisk.
    IMPORTANT: When recreating the partition, make sure that you
      1)  create it at the same disk sector (use sector as the unit!)
      2)  create it with the same partition type (usually 7, HPFS/NTFS)
      3)  do not make it smaller than the new NTFS filesystem size
      4)  set the bootable flag for the partition if it existed before
    Otherwise you won't be able to access NTFS or can't boot from the disk!
    If you make a mistake and don't have a partition table backup then you
    can recover the partition table by TestDisk or Parted's rescue mode.

Recreate the partition table entry:

::
$ fdisk -C 16253 -H 16 -S 63 winxp.raw 

We need DOS compatibility to be able to recreate a partition at sector 63:

::
    Command (m for help): c
    DOS Compatibility flag is set (DEPRECATED!)

Delete the original partition:

::
    Command (m for help): d
    Selected partition 1

Create new partition with the right size:

::
    Command (m for help): n
    Partition type:
       p   primary (0 primary, 0 extended, 4 free)
       e   extended
    Select (default p): p
    Partition number (1-4, default 1): 1
    First sector (63-266134527, default 63): 
    Using default value 63
    Last sector, +sectors or +size{K,M,G} (63-266134527, default 266134527): +16382953

Set partition type to NTFS:

::
    Command (m for help): t
    Selected partition 1
    Hex code (type L to list codes): 7
    Changed system type of partition 1 to 7 (HPFS/NTFS/exFAT)

Make partition bootable:

::
    Command (m for help): a
    Partition number (1-4): 1

Display partition table, write and quit:

::
    Command (m for help): p

    Disk winxp.raw: 136.3 GB, 136260878336 bytes
    16 heads, 63 sectors/track, 264022 cylinders, total 266134528 sectors
    Units = sectors of 1 * 512 = 512 bytes
    Sector size (logical/physical): 512 bytes / 512 bytes
    I/O size (minimum/optimal): 512 bytes / 512 bytes
    Disk identifier: 0xbe2ebe2e

        Device Boot      Start         End      Blocks   Id  System
    winxp.raw1   *          63    16383016     8191477    7  HPFS/NTFS/exFAT

    Command (m for help): w
    The partition table has been altered!

    Syncing disks.

Truncate the disk to the right size:

::
$ truncate -s 8388108288 winxp.raw 

Finally, convert the disk to Bochs's "sparse" image format, using the "bximage"
tool:

::
    $ bximage
    ========================================================================
                                    bximage
      Disk Image Creation / Conversion / Resize and Commit Tool for Bochs
                                      $Id$
    ========================================================================

    1. Create new floppy or hard disk image
    2. Convert hard disk image to other format (mode)
    3. Resize hard disk image
    4. Commit 'undoable' redolog to base image
    5. Disk image info

    0. Quit

    Please choose one [0] 2

    Convert image

    What is the name of the source image?
    [c.img] winxp.raw

    What should be the name of the new image?
    [winxp.raw] winxp.sparse.0

    What kind of image should I create?
    Please type flat, sparse, growing, vpc or vmware4. [flat] sparse

    source image mode = 'flat'
    hd_size: 8388108288
    sparse: pagesize = 0x8000, data_start = 0x100000

    Converting image file: [100%] Done.

Also create another empty sparse image of the same size:

::
    $ bximage
    ========================================================================
                                    bximage
      Disk Image Creation / Conversion / Resize and Commit Tool for Bochs
                                      $Id$
    ========================================================================

    1. Create new floppy or hard disk image
    2. Convert hard disk image to other format (mode)
    3. Resize hard disk image
    4. Commit 'undoable' redolog to base image
    5. Disk image info

    0. Quit

    Please choose one [0] 1

    Create image

    Do you want to create a floppy disk image or a hard disk image?
    Please type hd or fd. [hd] 

    What kind of image should I create?
    Please type flat, sparse, growing, vpc or vmware4. [flat] sparse

    Enter the hard disk size in megabytes, between 10 and 8257535
    [10] 8000

    What should be the name of the image?
    [c.img] winxp.sparse.1

    Creating hard disk image 'winxp.sparse.1' with CHS=16253/16/63

    The following line should appear in your bochsrc:
      ata0-master: type=disk, path="winxp.sparse.1", mode=sparse

Next, create a copy of this disk image:

$ cp winxp.sparse.1 winxp.sparse2

One benefit of the sparse image format is that the disk images can be stacked,
with writes only going to the topmost layer.

Next, configure Bochs (by editing .bochsrc) to use winxp.sparse.1, boot Bochs,
and wait until Windows is done checking the disk and setting up all devices.
Then, power off, configure Bochs to use winxp.sparse.2 and boot the emulator
again, wait until the system state stabilizes, i.e., wait until it stops
continuously accessing the disk. Then suspend the emulator, i.e., create a
snapshot of the running system. Store that snapshot and winxp.sparse.2
somewhere safe. 

Once you have all that ready, configure and build Bochs again, with
instrumentation enabled as outlined above.  After that you'll have to take a
few more steps, like setup a PostgreSQL database and create a CD image
containing an autorun.inf file for the sample you want to analyse.

Database and other configuration will need to be done in PyBochsConfig.py. Make
sure you add the instrument/python directory to your PYTHONPATH. You will also
need pydasm in your PYTHONPATH.

To start an analysis, run

::
$ cp -a winxp.sparse.2.saved winxp.sparse.2 
$ cp -a SUSPEND_DIRECTORY.saved SUSPEND_DIRECTORY
$ bochs -r SUSPEND_DIRECTORY



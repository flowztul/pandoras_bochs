Some build requesites on debian:
python-dev
libc6-dev
libpq-dev

For compiling Pandora's Bochs on a linux system (I didn't test it on Windows
yet), you'd have to configure it first, using the following command line:

./configure --enable-cpu-level=6 --enable-all-optimizations --with-x11
--with-term --with-nogui --enable-pci --enable-acpi --enable-usb-ohci
--enable-ne2000 --enable-pnic --enable-vbe --enable-clgd54xx --enable-sse=4
--enable-x86-debugger --enable-show-ips

Then use "make" to build it.

Create a disk image:

$ bximage 
========================================================================
                                bximage
                  Disk Image Creation Tool for Bochs
                                  $Id$
========================================================================

Do you want to create a floppy disk image or a hard disk image?
Please type hd or fd. [hd] 

What kind of image should I create?
Please type flat, sparse or growing. [flat] sparse

Enter the hard disk size in megabytes, between 1 and 129023
[10] 20480

I will create a 'sparse' hard disk image with
  cyl=41610
  heads=16
  sectors per track=63
  total sectors=41942880
  total size=20479.92 megabytes

What should I name the image?
[c.img] c.img.0

Writing: [] Done.

I wrote 21474754560 bytes to test.img.0.

The following line should appear in your bochsrc:
  ata0-master: type=disk, path="c.img.0", mode=sparse, cylinders=41610, heads=16, spt=63


Now, install Windows XP (please refer to the official Bochs documentation from
http://bochs.sourceforge.net if you need more information). Once that's done,
start the virtual machine and create a snapshot, using Bochs's "suspend"
feature. Next, create another disk image with the same parameters as above, but
name it c.img.1. Change your bochsrc to reference that file. Copy the new disk
image and the suspend snapshot to a safe location, so that you can restore your
machine state.

Once you have all that ready, configure the source code again, using the
above command, but add:

--with-postgresql --with-python --enable-instrumentation=instrument/python
--disable-repeat-speedups

Then, rebuild Bochs, again, using "make". After that you'd have to take
a few more steps, like setup a PostgreSQL database and create a CD image
containing an autorun.inf file for the sample you want to analyse.

Database and other configuration will need to be done in PyBochsConfig.py. Make
sure you add the instrument/python directory to your PYTHONPATH



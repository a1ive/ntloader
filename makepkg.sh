#!/bin/sh
mkdir -p raw
cd utils/rootfs
find * | cpio -o -H newc > ../initrd.cpio
cd ..
python lznt1.py initrd.cpio initrd.lz1
cd ..
cp utils/initrd.lz1 raw/
cp ntloader raw/
cp ntloader.i386 raw/
cp README.md raw/
cp LICENSE.txt raw/
zip -9 -r -j ntloader.zip raw

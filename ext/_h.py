# ============================================================
#  mkit_toolkit  ·  dev by Calmgh06
#  电子数据取证工具包  |  EWF / NTFS / ext4 / APFS / VMDK / LVM2 / RAID5
# ============================================================
import sys, os
sys.path.insert(0, r'E:\ALL\AAAI\Works\RE\meiya')
from mkit.image import Image, SubImage
from mkit.ext4 import Ext4
import mkit.volume as volume

_IMG = None
_FS = None

def getfs():
    global _IMG, _FS
    if _FS is None:
        _IMG = Image(r'F:\ALL\meiya\src\WKH-02\WKH-02\WKH-02.e01')
        p = volume.parse(_IMG)[1]
        _FS = Ext4(SubImage(_IMG, p['start'], p['size']))
    return _FS

def ls(path):
    fs = getfs()
    i = fs.lookup(path)
    return fs.listdir(i)

def rd(path):
    fs = getfs()
    i = fs.lookup(path)
    return fs.read_data(i)

def rdino(ino):
    fs = getfs()
    return fs.read_data(ino)

def walk(path):
    return getfs().walk(path)

def show(path):
    for e in ls(path):
        print(e.name, e.inode, e.file_type)

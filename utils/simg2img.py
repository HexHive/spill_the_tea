#!/usr/bin/env python
#encoding:utf8  

# Adapted from: https://gist.github.com/TwizzyIndy/8319d240a326a19422a97b998610a693

#===============================================================================  
#  
#          FILE:  simg2img.py  
#   
#         USAGE:  ./simg2img.py system.img   
#   
#   DESCRIPTION:    
#   
#        AUTHOR: Karl Zheng   
#       COMPANY: Meizu  
#       CREATED: 20111018 152515 CST  
#      REVISION:  ---  
#===============================================================================

#########
# Enhanced by Twizzy Indy
# June 13 2016

#########
# Updated by Michele Lizzit
# Mar 08 2022


import sys
import struct

VERBOSE = False
PROGRESS_BAR = True

if PROGRESS_BAR:
    from tqdm import tqdm

class ext4_file_header:  
    def __init__(self, buf):  
        self.magic, \
                self.major, \
                self.minor, \
                self.file_header_size, \
                self.chunk_header_size, \
                self.block_size, \
                self.total_blocks, \
                self.total_chunks, \
                self.crc32, \
                = struct.unpack('<IHHHHIIII', buf)  
  
class ext4_chunk_header:  
    def __init__(self, buf):  
        self.type,\
                self.reserved,\
                self.chunk_size,\
                self.total_size,\
                = struct.unpack('<HHII', buf)  

def simg2img(ifd, ofd):    
    # get filelen  
    ifd.seek(0, 2)  
    file_len = ifd.tell()  
    print(file_len) if VERBOSE else None
    ifd.seek(0, 0)

    buf = ifd.read(28)
    #print repr(buf)  
    file_header = ext4_file_header(buf)
    if file_header.file_header_size > 28:
        ifd.read(file_header.file_header_size - 28)
    
    EXT4_FILE_HEADER_MAGIC = 0xED26FF3A  
    EXT4_CHUNK_HEADER_SIZE = 12
    
    if file_header.magic != EXT4_FILE_HEADER_MAGIC:  
        print("Not a compressed ext4 fileecho")
        sys.exit(1)
    
    #print "file_header chunks:%X%" % (file_header.total_chunks)
    print("file_header.chunk_header_size: ", file_header.chunk_header_size) if VERBOSE else None
    print("file_header.file_header_size: ", file_header.file_header_size) if VERBOSE else None
    total_chunks = file_header.total_chunks  
    print("total chunks = %d" %(total_chunks)) if VERBOSE else None
    
    sector_base = 82528  
    output_len = 0  
    done_chunks = 0
    
    if PROGRESS_BAR:
        progress_bar = tqdm(total=file_header.total_blocks * file_header.block_size, unit='iB', unit_scale=True)

    while total_chunks > 0:  
        buf = ifd.read(EXT4_CHUNK_HEADER_SIZE)

        # Skip the remaining bytes in a header that is longer than expected
        if (file_header.chunk_header_size > EXT4_CHUNK_HEADER_SIZE):
            print(f"Skipping {file_header.chunk_header_size - EXT4_CHUNK_HEADER_SIZE} bytes in a longer chunk header") if VERBOSE else None
            ifd.read(file_header.chunk_header_size - EXT4_CHUNK_HEADER_SIZE)

        chunk_header = ext4_chunk_header(buf)
        sector_size = (chunk_header.chunk_size * file_header.block_size) >> 9;  
        print( "ct:%X, cs:%X, ts:%X, ss:%X" % (chunk_header.type, chunk_header.chunk_size, chunk_header.total_size, sector_size)) if VERBOSE else None
    
        data = b""
        if chunk_header.type == 0xCAC1:  # raw type   
            data = ifd.read(chunk_header.total_size - file_header.chunk_header_size)  
            if len(data) != (sector_size << 9):
                print("len data:%d, sector_size:%d" % (len(data), (sector_size << 9))) if VERBOSE else None
                print("Image is corrupted, exiting")
                sys.exit(1)  
            else:  
                print("len data:%d, sector_size:%d" % (len(data), sector_size << 9)) if VERBOSE else None
                ofd.write(data)
                output_len += len(data)  
                #print raw_chunk
                print("write raw data in %d size %d n" % (sector_base, sector_size)) if VERBOSE else None
                print("output len:%x" % (output_len)) if VERBOSE else None

                sector_base += sector_size  
        elif chunk_header.type == 0xCAC2:  # TYPE_FILL  
            data = b'\x00' * (sector_size << 9);  
            ifd.read(4)
            ofd.write(data)   
            output_len += len(data)  
            #print fill_chunk % n
            # print(f"TYPE_FILL len({sector_size << 9}) == len({chunk_header.chunk_size * file_header.block_size})")
            print("chunk_size:%x" % (chunk_header.chunk_size)) if VERBOSE else None
            print("output len:%x" % (output_len)) if VERBOSE else None
            sector_base += sector_size  
        elif chunk_header.type == 0xCAC3:  # TYPE_DONT_CARE 
            #print none chunk at chunk:%d%(file_header.total_chunks - total_chunks)
            #print(data_size:0x%x, chunk_size:%d, block_size:%d%(sector_size << 9, chunk_header.chunk_size, file_header.block_size))
            # print(f"Type dont care at {output_len:02X} len({sector_size << 9}) == len({chunk_header.chunk_size * file_header.block_size})")
            data = b'\x00' * (sector_size << 9)
            ofd.write(data)   
            output_len += len(data)  
            sector_base += sector_size  
        else:  
            print("ERR: Unknown type")
            sys.exit(1)
            
        total_chunks -= 1
        done_chunks += 1
        print("remain chunks = %d" % (total_chunks)) if VERBOSE else None

        if PROGRESS_BAR:
            progress_bar.update(len(data))
    
    if PROGRESS_BAR:
        progress_bar.close()

    print("write done") if VERBOSE else None

if __name__ == "__main__":
    if len(sys.argv) > 2:
        filename_in = sys.argv[1]  
        filename_out = sys.argv[2]  
    else:  
        print("No file is designated")
        sys.exit(1)

    with open(filename_in, "rb") as fin:
        with open(filename_out, "wb") as fout:
            simg2img(fin, fout)

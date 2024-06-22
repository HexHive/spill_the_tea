import os
import shutil
import io
import tarfile
import logging
import pexpect
import struct
import sys

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

def unify_tas(file_chunk_dir: str, fw_out_dir: str):

    # unify .mdt and .bXX to ELF
    # https://github.com/pandasauce/unify_trustlet/blob/master/unify_trustlet.py

    for filename in os.listdir(file_chunk_dir):
        if filename.endswith(".mdt"):
            chunk_path = os.path.join(file_chunk_dir, filename)
            filetype = pexpect.run(f"file -b {chunk_path}").decode()
            if filetype.startswith("data"):
                log.warning(f"Filetype data of {filename}")
                continue
            bitness = filetype.split(",")[0].split(" ")[1].split("-")[0]
            arch = filetype.split(",")[1]
            if "arm" not in arch.lower():
                log.warning(f"Arch of {filename} is not arm, it is {arch}")
                continue

            trustlet_name = filename[:-4]

            if bitness == "32":
                log.debug("bitness of %s is %s" % (filename, bitness))
                ELF_HEADER_SIZE = 0x34
                E_PHNUM_OFFSET = 0x2C
                PHDR_SIZE = 0x20
                P_FILESZ_OFFSET = 0x10
                P_OFFSET_OFFSET = 0x4

            elif bitness == "64":
                log.debug("bitness of %s is %s" % (filename, bitness))
                ELF_HEADER_SIZE = 0x40
                E_PHNUM_OFFSET = 0x38
                PHDR_SIZE = 0x38
                P_FILESZ_OFFSET = 0x20
                P_OFFSET_OFFSET = 0x8
            else:
                log.debug("bitness of %s is %s" % (filename, bitness))
                return

            # Reading the ELF header from the ".mdt" file
            mdt = open(os.path.join(chunk_path), "rb")
            elf_header = mdt.read(ELF_HEADER_SIZE)
            phnum = struct.unpack(
                "<H", elf_header[E_PHNUM_OFFSET : E_PHNUM_OFFSET + 2]
            )[0]
            log.debug(
                "[+] Found %d program headers in %s" % (phnum, trustlet_name)
            )

            # Reading each of the program headers and copying the relevant chunk
            output_file_path = os.path.join(fw_out_dir, f"{trustlet_name}.elf")
            output_file = open(output_file_path, "wb")
            for i in range(0, phnum):

                # Reading the PHDR
                # print "[+] Reading PHDR %d" % i
                phdr = mdt.read(PHDR_SIZE)
                p_filesz = struct.unpack(
                    "<I", phdr[P_FILESZ_OFFSET : P_FILESZ_OFFSET + 4]
                )[0]
                p_offset = struct.unpack(
                    "<I", phdr[P_OFFSET_OFFSET : P_OFFSET_OFFSET + 4]
                )[0]
                # print "[+] Size: 0x%08X, Offset: 0x%08X" % (p_filesz, p_offset)

                if p_filesz == 0:
                    # print "[+] Empty block, skipping"
                    continue  # There's no backing block

                # Copying out the data in the block
                block = open(
                    os.path.join(file_chunk_dir, f"{trustlet_name}.b{i:02d}"),
                    "rb",
                ).read()
                output_file.seek(p_offset, 0)
                output_file.write(block)
                block_path = os.path.join(file_chunk_dir, f"{trustlet_name}.b{i:02d}")
                os.system(f'cp {block_path} {fw_out_dir}/')

            output_file.close()
            mdt_file_path = os.path.join(fw_out_dir, filename)
            mdt.seek(0)
            log.debug(f"dumping mdt to {mdt_file_path}")
            with open(mdt_file_path, "wb") as f:
                f.write(mdt.read())
            mdt.close()
        if filename.endswith(".mbn"):
            chunk_path = os.path.join(file_chunk_dir, filename)
            filetype = pexpect.run(f"file -b {chunk_path}").decode()
            if filetype.startswith("data"):
                log.warn(f"Filetype data of {filename}")
                continue
            bitness = filetype.split(",")[0].split(" ")[1].split("-")[0]
            arch = filetype.split(",")[1]
            if "arm" not in arch.lower():
                log.warn(f"Arch of {filename} is not arm, it is {arch}")
                continue
            mdn_file_path = os.path.join(fw_out_dir, filename)
            mdn = open(os.path.join(chunk_path), "rb")
            log.debug(f"dumping mdn to {mdn_file_path}")
            with open(mdn_file_path, "wb") as f:
                f.write(mdn.read())
            mdn.close()

if len(sys.argv) < 3:
    print("usage: python3 unify path_to_chunks, path_to_out")
    print("creates elf and removes non arm64 bins")
    exit(0)

chunk_dir = sys.argv[1]
out_dir = sys.argv[2]
if not os.path.exists(out_dir):
    os.system(f"mkdir -p {out_dir}")
unify_tas(chunk_dir, out_dir)

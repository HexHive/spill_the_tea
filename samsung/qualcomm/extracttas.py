#!/usr/bin/env python
import sys
import argparse
import tempfile
import os
import shutil
import io
import tarfile
import logging
import pexpect
import struct
import fs
import pprint
import pyfatfs
import zipfile
import lz4

# local imports
from utils import dump_ext4, utils
from utils.utils import SPARSE_HEADER_MAGIC
from utils.simg2img import simg2img

# type hinting
from typing import List, Callable, BinaryIO, Tuple
################################################################################
# Logging
################################################################################

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# Globals
################################################################################

TMP_DIR = tempfile.mkdtemp()
TA_PARTITIONS = ["modem", "NON-HLOS", "Core_NON-HLOS"]

################################################################################
# Script begin (main at bottom)
################################################################################


def contains_tas(fw_archive_path: str) -> bool:
    """Does `fw_archive_path` contain trusted applications?

    For Samsung fimrmware archives, we are interested in the "AP_*" and "BL_*"
    archives.

    Args:
        fw_archive_path (str): path to an archive in a firmware update.

    Returns:
        bool: `True` if `fw_archive_path` contains TAs, `False` otherwise.
    """
    ret = False
    if os.path.basename(fw_archive_path)[:3] in ["AP_", "BL_"] or os.path.basename(fw_archive_path)[-12:-8] == "HOME" or os.path.basename(fw_archive_path)[-8:-4] == "HOME":
        if os.path.basename(fw_archive_path).endswith(".tar"):
            ret = True
        elif os.path.basename(fw_archive_path).endswith(".tar.md5"):
            ret = True
    return ret

def unlz4(ifp) -> io.BytesIO:
    """decompresses path, lz4 creates file without .lz4 extenson from path."""
    # TODO: use lz4.stream
    ifp.seek(0)
    out = lz4.frame.decompress(ifp.read())
    return io.BytesIO(out)


def unzip(
    zip_path: str, filter_func: Callable[[str], bool], out_dir: str
) -> List[str]:
    """Unzip files from archive under `zip_path` using `filter_func` as a
       filtering function for the files we want to extract.

    Args:
        zip_path (str): path to the zip archive
        Callable[[str], bool]: function taking a string argument and returning
                              `True` or `False` to indicate files we want to
                              extract.
        out_dir (str): output directory for the extracted files

    Returns:
        List[str]: a list of paths to the extracted files.
    """

    extracted_file_paths = []

    if not zipfile.is_zipfile(zip_path):
        log.error("{} is no .zip file.".format(zip_path))
        return None

    with zipfile.ZipFile(zip_path) as zip_ref:
        files_to_extract = [x for x in zip_ref.namelist() if filter_func(x)]
        for f in files_to_extract:
            log.info(f"Adding {f} to analyze queue")
            zip_ref.extract(f, path=out_dir)
            extracted_file_paths.append(os.path.join(out_dir, f))
    return extracted_file_paths


def get_tar_archives(firmware_path: str) -> List[BinaryIO]:
    """Get a list of relevant open file objects from `firmware_path`.

    Args:
        firmware_path (str): path to the firmware archive.

    Returns:
        List(BinaryIO): A list of open file objects.
    """

    # Create temporary dir for files
    tmp_dir = tempfile.mkdtemp(dir=TMP_DIR)

    extracted_files = []

    if zipfile.is_zipfile(firmware_path):
        # This firmware is a zipfile

        fw_name = os.path.basename(firmware_path)
        log.info(f"Detected firmware {fw_name} of type ZIPFILE")

        # Extract images from zipfile
        extracted_file_paths = unzip(firmware_path, contains_tas, tmp_dir)
        for path in extracted_file_paths:
            fd = open(path, "rb")
            extracted_files.append(fd)

    elif os.path.isdir(firmware_path):
        # If firmware is a folder with an already extracted firmware
        fw_name = os.path.basename(firmware_path)
        log.info(f"Detected firmware {fw_name} of type TARFOLDER")

        _tar_files = [x for x in os.listdir(firmware_path) if contains_tas(x)]
        for filename in _tar_files:
            log.info(f"Adding {filename} to analyze queue")
            fd = open(os.path.join(firmware_path, filename), "rb")
            extracted_files.append(fd)
    else:
        assert False, "This should never happen"
    return extracted_files


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


def extract_tas(extracted_images: List[Tuple[str, BinaryIO]], fw_out_dir: str):
    """Takes a list of (`image_name`, `fobj`) tuples and extracts all TAs in
       these images to `fw_out_dir`


    Args:
        extracted_images (List[Tuple[str, BinaryIO]]): (`image_name`, `fobj`)
                                                       tuples.
        fw_out_dir (str): output dir
    """

    for img_filename, img in extracted_images:
        if img is None:
            log.debug(f"Skipping NULL file {img_filename}")
            continue

        img.seek(0)

        if not img_filename.endswith(".img") and not img_filename.endswith(".bin"):
            log.debug(f"Skipping non-image file {img_filename}")
            continue

        if img_filename.startswith("boot.img"):
            log.debug(f"Skipping boot.img file")
            continue

        if not any([(x in img_filename) for x in TA_PARTITIONS]):
            log.debug(f"Skipping unrelevant image {img_filename}")
            continue

        if img.read(4) == SPARSE_HEADER_MAGIC[::-1]:
            # If image is sparse image, unsparse
            extimg = io.BytesIO()
            simg2img(img, extimg)
            img = extimg

        img.seek(0)

        tmpdir = tempfile.mkdtemp(dir=TMP_DIR)

        fat_img = fs.open_fs(f"fat://{img_filename}")
        ofs = fs.open_fs(f"osfs://{tmpdir}")

        file_patterns = ["*.mdt", "*.MDT", "*.b??", "*.B??", "*.mbn"]

        for img_path in fat_img.walk.files(filter=file_patterns):
            filename = os.path.basename(img_path)
            fs.copy.copy_file(fat_img, img_path, ofs, filename.lower())

        unify_tas(tmpdir, fw_out_dir)

        shutil.rmtree(tmpdir)
    return


def extract(firmware_path: str, out_dir: str, tas: bool = False) -> None:

    log.debug(f"extracting {firmware_path}... to {out_dir}")

    if not os.path.exists(out_dir):
        log.warn(f"Output dir {out_dir} does not exist. Creating...")
        os.mkdir(out_dir)

    fw_name = os.path.basename(os.path.normpath(firmware_path))
    fw_out_dir = os.path.join(out_dir, fw_name)
    if not os.path.exists(fw_out_dir):
        os.makedirs(fw_out_dir)
    else:
        log.warn("Output dir {} already exist.".format(fw_out_dir))
    print(fw_out_dir, "!!!")

    tar_archives = get_tar_archives(firmware_path)
    image_match_rule = lambda x: os.path.basename(x).endswith("modem.img") or os.path.basename(x).endswith("NON-HLOS.bin")
    extracted_images = list()
    for f in tar_archives:
        log.debug(f"Processing tarball {os.path.basename(f.name)}")
        with tarfile.open(fileobj=f) as tar:
            files_to_extract = [x for x in tar.getnames() if image_match_rule(x)]
            for f in files_to_extract:
                log.info(f"Adding {f} to analyze queue")
                tar.extract(f, path=fw_out_dir)
                fd = open(os.path.join(fw_out_dir, f), "rb")
                extracted_images.append((fd.name, fd))

    

    # create temporary dir for files
    tmp_dir = tempfile.mkdtemp(dir=TMP_DIR)
    log.debug(f"tmp dir is {tmp_dir}")

    extract_tas(extracted_images, fw_out_dir)

    return


def multi_extract(fw_dir, our_dir, tas=False):
    fw_paths = [
        os.path.join(fw_dir, fw_name)
        for fw_name in os.listdir(fw_dir)
        if fw_name.endswith(".zip")
    ]

    for fw_path in fw_paths:
        extract(fw_path, our_dir, tas)


def setup_args():
    """Argument parser setup."""
    parser = argparse.ArgumentParser()
    single_fw_group = parser.add_mutually_exclusive_group()
    single_fw_group.add_argument(
        "-f",
        "--firmware",
        action="store",
        dest="firmware",
        help="Extracts contents specified by other flags from provided firmware image.",
    )

    multi_fw_group = parser.add_mutually_exclusive_group()
    multi_fw_group.add_argument(
        "-m",
        "--multi",
        action="store",
        dest="firmware_dir",
        help="Extracts contents specified by other flags from all firmware images "
        "contained in firmware_dir.",
    )
    parser.add_argument(
        "-t",
        "--tas",
        action="store_true",
        help="Get trusted applications from image.",
    )
    parser.add_argument(
        "-o",
        "--out",
        required=True,
        action="store",
        help="Directory to store outputs.",
    )
    return parser


def main():
    """This main method only invokes other methods according to the supplied args."""
    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.firmware:
        extract(args.firmware, args.out, args.tas)
    elif args.firmware_dir:
        multi_extract(args.firmware_dir, args.out, args.tas)
    else:
        arg_parser.print_help()

    sys.exit(0)


if __name__ == "__main__":
    main()

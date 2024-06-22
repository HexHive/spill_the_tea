#!/usr/bin/env python
import sys
import argparse
import tempfile
import os
import shutil
import zipfile
import tarfile
import logging
import io
import lz4.frame

# local imports
from utils import dump_ext4, utils
from utils.utils import SPARSE_HEADER_MAGIC
from utils.simg2img import simg2img
from utils import lpunpack
import sboot2mclf

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
TA_PARTITIONS = ["system", "vendor", "super"]
VERBOSE = True

################################################################################
# Script begin (main at bottom)
################################################################################


def unsuper(super_file_path, out_dir):
    """Extracts all partitions included in a super image (s20).

    Expects a superunpack binary in sparseimg folder.
    Taken from: https://github.com/munjeni/super_image_dumper
    """
    cmd = []
    cmd.append("./superunpack")
    cmd.append(super_file_path)
    cmd.append(out_dir)
    _, _, err = utils.system(cmd)
    if err:
        log.error("superunpack: {}".format(err))
    return


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


def extract_images(files: List[BinaryIO]) -> List[Tuple[str, BinaryIO]]:
    """Extract relevant images from `files`.

    Args:
        files (List[BinaryIO]): list of open file objects.

    Returns:
        List[BinaryIO]: list of file objects of relevant images
    """

    extracted_images = list()
    for f in files:
        log.debug(f"Processing tarball {os.path.basename(f.name)}")
        with tarfile.open(fileobj=f) as tf:
            for tm in tf:
                log.debug(f"Extracting {tm.name} from tarball")
                ef = tf.extractfile(tm)
                en = tm.name

                # first extract from lz4 if necessary
                if tm.name.endswith(".lz4"):
                    ef = unlz4(ef)
                    en = en[:-4]

                extracted_images.append((en, ef))
    return extracted_images


def extract_from_super_image(super_img: BinaryIO) -> List[Tuple[str, BinaryIO]]:
    """Unpack super image and return file objects to the `vendor` and `system`
       images.

    Args:
        super_img (BinaryIO): file object to the super image

    Returns:
        List[Tuple[str, BinaryIO]]: list of file objects to the `vendor` and
                                    `system` images.
    """

    extracted_images = list()

    # If image is sparse image, unsparse
    if super_img.read(4) == SPARSE_HEADER_MAGIC[::-1]:
        extimg = io.BytesIO()
        simg2img(super_img, extimg)
        super_img = extimg

    super_img.seek(0)

    extracted_images.append(
        ("system.img", lpunpack.LpUnpack(super_img, "system").unpack())
    )
    extracted_images.append(
        ("vendor.img", lpunpack.LpUnpack(super_img, "vendor").unpack())
    )
    return extracted_images


def extract_tas(extracted_images: List[Tuple[str, BinaryIO]], fw_out_dir: str):

    for img_filename, img in extracted_images:
        if img is None:
            log.debug(f"Skipping NULL file {img_filename}")
            continue

        img.seek(0)

        if not img_filename.endswith(".img"):
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

        tmpdir = tempfile.mkdtemp()

        # TODO: is this regex correct to find TAs?
        dump_ext4.dump_folder(
            img,
            "",
            tmpdir,
            file_regex=[".*-0000-0000-0000-.*", ".*\.tlbin"],
        )

        # up to galaxy s9
        ta_paths = utils.find_files(tmpdir, "*.tlbin")
        # galaxy s10
        ta_paths_s10 = utils.find_files(tmpdir, "*-0000-0000-0000-*")

        if ta_paths or ta_paths_s10:
            tas_dstdir = os.path.join(fw_out_dir, "tas")
            if not os.path.exists(tas_dstdir):
                os.mkdir(tas_dstdir)
            for ta_path in ta_paths + ta_paths_s10:
                shutil.copy(ta_path, tas_dstdir)
                pathfile = os.path.join(
                    tas_dstdir, os.path.basename(ta_path) + "_origpath.txt"
                )
                with open(pathfile, "w") as pf:
                    pf.write(os.path.normpath(ta_path.lstrip(tmpdir)))
                    pf.write("\n")
        else:
            log.error("Could not find TAs in {} ({})".format(img, tmpdir))
        shutil.rmtree(tmpdir)


def extract_sboot(sboot: BinaryIO, out_dir: str):
    """Handle sboot extraction."""
    tas_dstdir = os.path.join(out_dir, "tas_sboot")
    if not os.path.exists(tas_dstdir):
        os.mkdir(tas_dstdir)
    sboot2mclf.extract(sboot, tas_dstdir)


def extract_bootimg(bootimg: BinaryIO, out_dir: str):
    """Handle bootimg extraction."""
    tas_dstdir = os.path.join(out_dir, "startup_tzar")
    if not os.path.exists(tas_dstdir):
        os.mkdir(tas_dstdir)

    tzar = utils.kernel_from_bootimg(bootimg)

    # Locate the startup.tzar archive
    tzar_bytes = tzar.read()

    if tzar_bytes.count(utils.TZAR_MAGIC) < 1:
        log.error("ERROR: no startup.tzar found in boot.img")
    elif tzar_bytes.count(utils.TZAR_MAGIC) > 1:
        log.error(
            "ERROR: multiple matches for startup.tzar magic bytes."
            " TAs in startup.tzar might not be extracted correctly"
        )
    else:
        log.info("Successfully located startup.tzar")

    # Extract TAs from tzar
    extracted_tas = []
    if tzar_bytes.count(utils.TZAR_MAGIC) > 0:
        tzar_offset = tzar_bytes.find(utils.TZAR_MAGIC)
        tzar.seek(tzar_offset)
        extracted_tas = utils.unpack_tzar(tzar)

    # Write to destination dir
    for ta in extracted_tas:
        fname, ta = ta
        if fname[0] == "/":
            fname = "." + fname

        fname = os.path.join(tas_dstdir, fname)
        dirpath = os.path.dirname(fname)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

        with open(fname, "wb") as taf:
            taf.write(ta.read())


def extract(firmware_path, out_dir, tas=False):

    # normalize fw path
    firmware_path = os.path.normpath(firmware_path)
    log.debug(f"Extracting {firmware_path}...")

    if not os.path.exists(out_dir):
        log.warning("Output dir {} does not exist. Creating...".format(out_dir))
        os.mkdir(out_dir)

    fw_out_dir = os.path.join(out_dir, os.path.basename(firmware_path))
    if not os.path.isdir(fw_out_dir):
        os.mkdir(fw_out_dir)

    if not os.path.exists(TMP_DIR):
        os.mkdir(TMP_DIR)

    # get relevant tar archives from `firmware_path`
    tar_archives = get_tar_archives(firmware_path)
    extracted_images = extract_images(tar_archives)

    sboot = None
    bootimg = None
    super_img_idx = None
    for idx, name_fobj in enumerate(extracted_images):
        name, fobj = name_fobj

        # Find sboot
        if name.startswith("sboot.bin"):
            sboot = fobj

        # Find boot.img (contains startup.tzar)
        if name.startswith("boot.img"):
            bootimg = fobj

        # find super image if it exists
        if name == "super.img":
            super_img_idx = idx

    if super_img_idx is not None:
        _, fobj = extracted_images[super_img_idx]
        del extracted_images[super_img_idx]
        extracted_images.extend(extract_from_super_image(fobj))

    if tas:
        extract_tas(extracted_images, fw_out_dir)

        if sboot:
            extract_sboot(sboot, fw_out_dir)

        if bootimg:
            # extract startup.tzar
            extract_bootimg(bootimg, fw_out_dir)

    for f in tar_archives:
        # close fobj and delete tarball if we unpacked to out dir
        f.close()
        #if out_dir in f.name:
        #    os.unlink(f.name)

    # delete temporary dir
    shutil.rmtree(TMP_DIR)
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

    sys.exit()


if __name__ == "__main__":
    main()

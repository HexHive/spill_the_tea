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
import subprocess
from utils import dump_ext4, utils, dump_erofs

from utils.simg2img import simg2img
from utils import lpunpack

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

SPARSE_HEADER_MAGIC = b"\xED\x26\xFF\x3A"
TMP_DIR = tempfile.mkdtemp()
TA_PARTITIONS = ["system", "vendor", "vendor_a", "super"]
VERBOSE = True


def extract(firmware_path, out_dir, tas=False):
    """
    Philipp: Firmware is the .tgz file downloaded from -> out_dir/fw_name/tas/..
    """
    log.debug("Extracting {}...".format(firmware_path))
    if not os.path.exists(out_dir):
        log.warning("Output dir {} does not exist. Creating...".format(out_dir))
        os.mkdir(out_dir)

    if not os.path.exists(TMP_DIR):
        os.mkdir(TMP_DIR)

    # Create temporary dir for files
    tmp_dir = tempfile.mkdtemp(dir=TMP_DIR)

    extracted_images = []

    # If firmware is a tgz
    fw_tgz_name = os.path.basename(os.path.normpath(firmware_path))
    if os.path.isfile(firmware_path):
        if not fw_tgz_name.endswith(".tgz"):
            log.error("{} is no .tgz file.".format(firmware_path))
            return None
        log.info(f"Detected firmware {fw_tgz_name} of type tgz")

        fw_name = firmware_path.split("/")[-2]
        fw_out_dir = os.path.join(out_dir, fw_name)

        # Extract images from zipfile
        with tarfile.open(firmware_path) as tgz_ref:
            for f in tgz_ref.getnames():
                if "super.img" in f.lower():
                    log.info(f"Adding {f} to analyze queue")
                    bio = io.BytesIO(tgz_ref.extractfile(f).read())
                    extracted_images.append(("super.img",bio))
                if "vendor.img" in f.lower():
                    log.info(f"Adding {f} to analyze queue")
                    bio = io.BytesIO(tgz_ref.extractfile(f).read())
                    extracted_images.append(("vendor.img",bio))

    else:
        assert False, "This should never happen"

    # Create output directory
    if not os.path.exists(fw_out_dir):
        os.mkdir(fw_out_dir)
    else:
        log.warn("Output dir {} already exist.".format(fw_out_dir))

    # Unpack super images
    for e in extracted_images:
        image_filename, image_file = e
        if image_filename == "super.img":
            # If image is sparse image, unsparse
            if image_file.read(4) == SPARSE_HEADER_MAGIC[::-1]:
                extimg = io.BytesIO()
                simg2img(image_file, extimg)
                image_file = extimg
            else:
                log.error("super.img isn't an Android SPARC image?!?")
                return None
            image_file.seek(0)

            vendor_partitions = ["vendor", "vendor_a"]
            for vendor_part in vendor_partitions:
                try:
                    extracted_images.append((f"{vendor_part}.img", lpunpack.LpUnpack(image_file, vendor_part).unpack() ))
                except lpunpack.LpUnpackError:
                    log.info(f"vendor partition {vendor_part} not found!")

            extracted_images.remove(e)
            break

    if tas:
        for image_filename, image_file in extracted_images:
            if image_file is None:
                log.debug(f"Skipping NULL file {image_filename}")
                continue

            image_file.seek(0)
            simg = image_file

            if (not image_filename.endswith(".img")) or image_filename.startswith("boot.img"):
                log.debug(f"Skipping non-image file {image_filename}")
                continue

            if not any([ (x in image_filename) for x in TA_PARTITIONS ]):
                log.debug(f"Skipping non-useful image {image_filename}")
                continue

            # If image is sparse image, unsparse
            if simg.read(4) == SPARSE_HEADER_MAGIC[::-1]:
                log.debug(f"Another sparse image file: {image_filename}!?!?")
                extimg = io.BytesIO()
                simg2img(simg, extimg)
                simg = extimg
            simg.seek(0)

            tmpdir = tempfile.mkdtemp()  

            mounted = False
            ext4_fail = False
            erofs_fail = False
            # try ext4 extraction, if it fails it may be an erofs 
            try:
                log.debug(f"dumping ext4 files for: {image_filename}")
                dump_ext4.dump_folder(simg, "", tmpdir, file_regex = [ ".*\.ta"])
            except Exception as e:
                log.error(f"failed ext4 for {image_filename}, {e}")
                ext4_fail = True
            if ext4_fail:
                try:
                    simg.seek(0)
                    log.debug(f"dumping erofs files for: {image_filename}")
                    dump_erofs.dump_folder(simg, "", tmpdir, file_regex = [ ".*\.ta"])
                except Exception as e: 
                    erofs_fail = True
                    log.error(f"failed erofs for {image_filename}, {e}")
                    
            if erofs_fail:
                # ok let's just mount it 
                mounted = True
                tmpfile = tempfile.mkstemp()[1]
                simg.seek(0)
                open(tmpfile, "wb").write(simg.getbuffer())
                os.system(f"rm -rf {tmpdir}/*")
                p = subprocess.Popen([f"sudo mount -t auto -o loop {tmpfile} {tmpdir}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.wait()
                out = p.stdout.read()
                err = p.stderr.read()

            ta_paths = utils.find_files(tmpdir, "*.ta")

            if ta_paths:
                tas_dstdir = os.path.join(fw_out_dir, "tas")
                if not os.path.exists(tas_dstdir):
                    os.mkdir(tas_dstdir)
                for ta_path in ta_paths:
                    log.debug(f"extracting {os.path.basename(ta_path)} to {tas_dstdir}")
                    if mounted:
                        # read-only filesystem
                        data = open(ta_path, "rb").read()
                        open(os.path.join(tas_dstdir, os.path.basename(ta_path)), "wb").write(data)
                    else:
                        shutil.copy(ta_path, tas_dstdir)
                    pathfile = os.path.join( tas_dstdir, os.path.basename(ta_path) + "_origpath.txt" )
                    with open(pathfile, "w") as pf:
                        pf.write( os.path.normpath( ta_path.lstrip(tmpdir) ) )
                        pf.write("\n")
            else:
                log.error("Could not find TAs in {} ({})".format(image_filename, tmpdir))
            if mounted:
                p = subprocess.Popen([f"sudo umount {tmpdir}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.wait()
            shutil.rmtree(tmpdir)
            if mounted:
                os.remove(tmpfile)


    # delete temporary dir
    shutil.rmtree(TMP_DIR)
    return fw_out_dir

def multi_extract(fw_dir, our_dir, tas=False):
    fw_paths = [os.path.join(fw_dir, fw_name) for fw_name in os.listdir(fw_dir) if fw_name.endswith(".tgz")]

    for fw_path in fw_paths:
        extract(fw_path, our_dir, tas)


def setup_args():
    """ Argument parser setup. """
    parser = argparse.ArgumentParser()
    single_fw_group = parser.add_mutually_exclusive_group()
    single_fw_group.add_argument("-f", "--firmware", action='store', dest='firmware',
                       help='Extracts contents specified by other flags from provided firmware image.')

    multi_fw_group = parser.add_mutually_exclusive_group()
    multi_fw_group.add_argument("-m", "--multi", action='store', dest='firmware_dir',
                                 help='Extracts contents specified by other flags from all firmware images '
                                      'contained in firmware_dir.')
    parser.add_argument("-t", "--tas", action="store_true", help="Get trusted applications from image.")
    parser.add_argument("-o", "--out", required=True, action="store", help="Directory to store outputs.")
    return parser


def main():
    """ This main method only invokes other methods according to the supplied args."""
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

#!/usr/bin/python3
import os
import argparse
import tempfile

"""
extract tas from a firmware downloaded from https://firmwarefile.com/category/oppo
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--firmware", action='store', dest='firmware',
                       help='Specify firmware file')
    parser.add_argument("-t", "--tas", action="store_true", help="Get trusted applications from image.")
    parser.add_argument("-o", "--out", required=True, action="store", help="Directory to store outputs.")
    args = parser.parse_args()

    tmpdir = tempfile.mktemp()

    if not os.path.exists(args.out):
        os.makedirs(args.out)

    fw_path = os.path.dirname(args.firmware)
    os.system(f"unzip -o '{args.firmware}' -d {tmpdir}")
    vendor_img = None
    super_img = None
    for root, dirs, files in os.walk(tmpdir):
        for f in files:
            if f == "vendor.img":
                vendor_img = os.path.join(root, f)
            if f == "super.img":
                super_img = os.path.join(root, f)
    if not vendor_img and not super_img:
        print("vendor.img or super.img not found at: ", tmpdir)
        exit(-1)
    if vendor_img:
        vendor_raw = os.path.join(tmpdir, "vendor.raw")
        vendor_out = os.path.join(tmpdir, "vendor_out")
        os.system(f"simg2img '{vendor_img}' {vendor_raw}")
        os.system(f"mkdir {vendor_out}")
        os.system(f"sudo mount -t auto -o ro {vendor_raw} {vendor_out}")
        os.system(f"cp {vendor_out}/thh/* {args.out}")
        os.system(f"cp {vendor_out}/thh/ta/* {args.out}")
        os.system(f"sudo umount {vendor_out}")
    if super_img:
        super_raw = os.path.join(tmpdir, "super.raw")
        super_out = os.path.join(tmpdir, "super_out")
        os.system(f"simg2img '{super_img}' {super_raw}")
        os.system(f"lpunpack {super_raw} {super_out}")
        os.system(f"mkdir {tmpdir}/vendor")
        if os.path.exists(f"{super_out}/vendor.img"):
            v_name = os.path.join(super_out, "vendor.img")
        else:
            v_name = os.path.join(super_out, "vendor_a.img")
        os.system(f"sudo mount -t auto -o ro {v_name} {tmpdir}/vendor")
        os.system(f"cp {tmpdir}/vendor/thh/* {args.out}")
        os.system(f"cp {tmpdir}/vendor/thh/ta/* {args.out}")
        os.system(f"sudo umount {tmpdir}/vendor")
    
    os.system(f"rm -r {tmpdir}")

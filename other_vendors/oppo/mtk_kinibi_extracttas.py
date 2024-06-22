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
    ofp_filename = None
    super_files = []
    for root, dirs, files in os.walk(tmpdir):
        for f in files:
            if f.endswith(".ofp"):
                ofp_filename = os.path.join(root, f)
            if f.startswith("super") and f.endswith("img"):
                super_files.append(os.path.join(root, f))
    if not ofp_filename:
        if len(super_files) == 0:
            print(".ofp file or super.img not found, please check manually at: ", tmpdir)
            exit(-1)
        super_raw = os.path.join(tmpdir, "super.raw")
        super_out = os.path.join(tmpdir, "super_out")
        print(f"simg2img {' '.join(super_files)} {super_raw}")
        os.system(f"simg2img {' '.join(super_files)} {super_raw}")
        os.system(f"lpunpack {super_raw} {super_out}")
        os.system(f"mkdir {os.path.join(tmpdir, 'vendor')}")
        os.system(f"sudo mount -t auto -o ro {os.path.join(super_out, 'vendor.img')} {os.path.join(tmpdir, 'vendor')}")
        os.system(f"cp -r {os.path.join(tmpdir, 'vendor', 'app', 'mcRegistry', '*')} {args.out}")
        os.system(f"sudo umount {os.path.join(tmpdir, 'vendor')}")
        os.system(f"rm -rf {tmpdir}")
    else:
        tmpdir2 = tempfile.mktemp()
        print(f"python3 oppo_decrypt/ofp_mtk_decrypt.py '{os.path.join(fw_path, ofp_filename)}' {tmpdir2}")
        os.system(f"python3 oppo_decrypt/ofp_mtk_decrypt.py '{os.path.join(fw_path, ofp_filename)}' {tmpdir2}")
        vendor = os.path.join(tmpdir2, "vendor.img")
        vendor_raw = os.path.join(tmpdir2, "vendor.raw")
        system = os.path.join(tmpdir2, "system.img")
        system_raw = os.path.join(tmpdir2, "system.raw")
        super = []
        for f in os.listdir(tmpdir2):
            if f.startswith("super") and f.endswith("img"):
                super.append(os.path.join(tmpdir2, f))
        super_raw = os.path.join(tmpdir2, "super.raw")
        super_out = os.path.join(tmpdir2, "super_out")
        if os.path.exists(os.path.join(vendor)):
            os.system(f"mkdir {os.path.join(tmpdir2, 'vendor')}")
            os.system(f"simg2img {vendor} {vendor_raw}")
            os.system(f"sudo mount -t auto -o ro {vendor_raw} {os.path.join(tmpdir2, 'vendor')}")
            os.system(f"cp -r {os.path.join(tmpdir2, 'vendor', 'app', 'mcRegistry', '*')} '{args.out}'")
            os.system(f"sudo umount {os.path.join(tmpdir2, 'vendor')}")
        if os.path.exists(os.path.join(system)):
            os.system(f"mkdir {os.path.join(tmpdir2, 'system')}")
            os.system(f"simg2img {system} {system_raw}")
            os.system(f"sudo mount -t auto -o ro {system_raw} {os.path.join(tmpdir2, 'system')}")
            os.system(f"cp -r {os.path.join(tmpdir2, 'system', 'vendor', 'app', 'mcRegistry', '*')} '{args.out}'")
            os.system(f"sudo umount {os.path.join(tmpdir2, 'system')}")    
        if len(super) > 0:
            os.system(f"simg2img {' '.join(super)} {super_raw}")
            os.system(f"lpunpack {super_raw} {super_out}")
            os.system(f"mkdir {os.path.join(tmpdir2, 'vendor')}")
            os.system(f"sudo mount -t auto -o ro {os.path.join(super_out, 'vendor.img')} {os.path.join(tmpdir2, 'vendor')}")
            os.system(f"cp -r {os.path.join(tmpdir2, 'vendor', 'app', 'mcRegistry', '*')} '{args.out}'")
            os.system(f"sudo umount {os.path.join(tmpdir2, 'vendor')}")

        if len(os.listdir(args.out)) == 0:
            print("failed to extract, check at", tmpdir2)
        else:
            os.system(f"rm -rf {tmpdir}")
            os.system(f"rm -rf {tmpdir2}")
        

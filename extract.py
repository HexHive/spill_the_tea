#!/usr/bin/env python
import sys
import os
import glob
import shutil
import logging

################################################################################
# Logging
################################################################################

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

################################################################################
# Globals
################################################################################

SCRIPTS = [
    "./xiaomi/qualcomm/extracttas.py",
    "./xiaomi/mediatek/extracttas.py",
    "./samsung/qualcomm/extracttas.py",
    "./samsung/kinibi/extracttas.py",
    "./samsung/teegris/extracttas.py",
    "./other_vendors/vivo/mtk_kinibi_extracttas.py",
    "./other_vendors/vivo/qc_extracttas.py",
    "./other_vendors/transsien/mtk_bp_extracttas.py",
    "./other_vendors/oppo/mtk_kinibi_extracttas.py",
    "./other_vendors/oppo/qc_extracttas.py",
]

################################################################################
# Code
################################################################################

def main(image_path: str, out_dir: str):
    for script in SCRIPTS:
        log.info(f"Trying {script}")
        shutil.rmtree(out_dir)
        os.mkdir(out_dir)
        cmd = f"{script} -t -f {image_path} -o {out_dir}"
        status = os.system(cmd)
        success = False
        for path in (glob.glob(f"{out_dir}/*/tas/*") + glob.glob(f"{out_dir}/tas/*")):
            log.info(f"Current path: {path}")
            if os.path.isfile(path):
                success = True
                break

        if success:
            log.info(f"Success with {script}")
            break


def usage():
    print(f"{sys.argv[0]} <image> <out_dir>")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
        exit(1)

    image_path = sys.argv[1]
    out_dir = sys.argv[2]

    if not os.path.isfile(image_path):
        usage()
        exit(1)

    main(image_path, out_dir)
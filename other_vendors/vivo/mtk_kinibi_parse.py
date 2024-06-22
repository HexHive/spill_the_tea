#!/usr/bin/python3
import os
import json
from ctypes import *
import argparse




parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dir_extract", action="store_true", help="set to extract all trusted applications in a directory")
parser.add_argument("-p", "--path", type=str, required=True, help="path to mdt file or folder with mdt files")
parser.add_argument("-o", "--output_path", type=str, required=True, help="path where to write report.json")
args = parser.parse_args()

if not os.path.exists(args.output_path):
    print("[-] output path doesn't exist, exiting")
    exit(-1)

if args.dir_extract:
    output_json = []
    for f in os.listdir(args.path):
        if f.endswith("mclf"):
            trustlet = open(os.path.join(args.path, f), "rb").read()
            rollback_version = int.from_bytes(trustlet[0x48:0x4c], "little")
            out = {}
            out["filename"] = f
            out["rollback_version"] = rollback_version
            out["header_bytes"] = trustlet[:8].hex()
            if trustlet[:4] == b"MCLF":
                out["is_mclf_format"] = True
            else:
                out["is_mclf_format"] = False
            output_json.append(out)
    with open(os.path.join(args.output_path, "report.json"), "w+") as f:
        f.write(json.dumps(output_json, indent=2))

else:
    print("please specify -d")
    exit(0)


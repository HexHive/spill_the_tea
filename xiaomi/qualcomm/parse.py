#!/usr/bin/python3
import OpenSSL.crypto
import sys
import os
import json
from cryptography.hazmat.primitives import serialization
import copy
from ctypes import *
import argparse


"""
http://bits-please.blogspot.com/2016/04/exploring-qualcomms-secure-execution.html
https://github.com/pandasauce/unify_trustlet/blob/master/unify_trustlet.py
input: mdt file, extracted certifcates and writes the extracted cert hashes to a file
cross-loading: possible if the signature certificate is the same?
"""

class secboot_metadata(Structure):
    # |  a  |  b  |     c     |
    #  XX XX XX XX XX XX XX XX

    _fields_ = [
        ("major_version", c_uint32),
        ("minor_version", c_uint32),
        ("sw_id", c_uint32),
        ("hw_id", c_uint32),
        ("oem_id", c_uint32),
        ("model_id", c_uint32),
        ("secondary_sw_id", c_uint32),
        ("flags", c_uint32),
        ("soc_vers", 12*c_uint32),
        ("serial_num", 8*c_uint32),
        ("root_cert_sel", c_uint32),
        ("anti_rollback", c_uint32)
    ]


def parse_new_mdt(mdt, output_json):
    """
    parse the new mdt
    struct secboot_metadata_type {
  uint32 major_version;
  uint32 minor_version;
  uint32 sw_id;
  uint32 hw_id;
  uint32 oem_id;
  uint32 model_id;
  uint32 secondary_sw_id;
  uint32 flags;
  uint32 soc_vers[12];
  uint32 serial_num[8];
  uint32 root_cert_sel;
  uint32 anti_rollback;
} secboot_metadata_type_A;
    """
    mdt_orig = copy.deepcopy(mdt)
    full_fail = False
    while True:
        meta_start = mdt.find(b"\x04\x00\x00\x00\x06\x00\x00\x00")
        if meta_start == -1:
            meta_start = mdt.find(b"\x00\x00\x00\x00\x06\x00\x00\x00")
            if meta_start == -1:
                # everything has failed, let's look for
                if full_fail:
                    print("[!!] failed to extract the certificate!!!")
                    return output_json
                mdt = mdt_orig
                full_fail = True
                meta_start = 0x1000  
        metadata_bytes = mdt[meta_start+48:meta_start+48+120]
        metadata = secboot_metadata()
        memmove(pointer(metadata), metadata_bytes, sizeof(metadata))
        print(metadata_bytes.hex(), bytes(mdt[meta_start: meta_start+48]).hex())
        print(metadata.anti_rollback, metadata.oem_id)
        if metadata.oem_id != 114:
            print("incorrect, keep searching!")
            meta_start += 1
            mdt = mdt[meta_start:]
        else:
            break
    output_json["anti_rollback"] = metadata.anti_rollback
    output_json["sw_id"] = metadata.sw_id
    output_json["secondary_sw_id"] = metadata.secondary_sw_id
    output_json["oem_id"] = metadata.oem_id
    output_json["hw_id"] = metadata.hw_id
    output_json["model_id"] = metadata.model_id
    return output_json



def parse_mdt(mdt):
    """
    input: mdt file bytes: returns a list of certificates and the information json
    """
    old_mdt = copy.deepcopy(mdt)
    certs = []
    cert_bytes = []
    offset = 0
    while True:
        ind = mdt.find(b"\x30\x82")
        if ind == -1:
            break
        offset += ind + 2
        try:
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, mdt[ind:]
            )
            certs.append(cert)
            cert_bytes.append(cert.to_cryptography().public_bytes())
        except:
            pass
        mdt = mdt[ind + 2 :]

    output_json = {}
    output_json["certs"] = []
    for cert in certs:
        print(cert.get_subject().get_components())
        data = {
                "subject": f"CN={cert.get_subject().CN},O={cert.get_subject().O},OU={cert.get_subject().OU},C={cert.get_subject().C}",
                "sha256": cert.digest("sha256").decode(),
                "notbefore": cert.get_notBefore().decode(),
                "notafter": cert.get_notAfter().decode(),
                "serialnumber": cert.get_serial_number(),
                "issuer": f"CN={cert.get_issuer().CN},O={cert.get_issuer().O},OU={cert.get_issuer().OU},C={cert.get_issuer().C}",
            }
        # find custom OU attributes
        for name, value in cert.get_subject().get_components():
            name = name.decode()
            value = value.decode()
            if not name == "OU":
                continue
            if not len(value.split(" ")) == 3:
                continue
            nr, k, OUtype = value.split(" ")
            if nr not in ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13"]:
                continue
            if "SW_ID" == OUtype:
                version = k[0:8]
                image_id = k[8:]
                output_json["SW_ID"] = int(k, 16)
                output_json["Version"] = int(version, 16)
                output_json["Image_ID"] = int(image_id, 16)
            elif "HW_ID" == OUtype:
                MSM_ID = k[0:8]
                output_json["MSM_ID"] = int(MSM_ID,16)
            else:
                output_json[OUtype] = int(k, 16)
        output_json["certs"].append(data)
        # handle the case when newer mdt versions are used
    if "Version" not in output_json:
        print("mdt is newer version, handling new mdt parsing")
        output_json = parse_new_mdt(old_mdt, output_json)
        output_json["old_mdt"] = False
    else:
        output_json["old_mdt"] = True
    return output_json, cert_bytes


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
    print("afd")
    for f in os.listdir(args.path):
        print(f)
        if f.endswith(".mdt"):
            ta_name = f.split(".mdt")[0]
            mdt_data, cert_bytes = parse_mdt(open(os.path.join(args.path, f), "rb").read())
            mdt_data["ta_name"] = ta_name
            output_json.append(mdt_data)
        if f.endswith(".mbn"):
            ta_name = f.split(".mbn")[0]
            mdt_data, cert_bytes = parse_mdt(open(os.path.join(args.path, f), "rb").read())
            mdt_data["ta_name"] = ta_name
            output_json.append(mdt_data)
    with open(os.path.join(args.output_path, "report.json"), "w+") as f:
        f.write(json.dumps(output_json, indent=2))

else:
    if args.path.endswith("mdt"):
        ta_name = args.path.strip(".mdt")
    elif args.path.endswith("mbn"):
        ta_name = args.path.strip(".mbn")
    else:
        print("you sure this is a tA?")
        exit(-1)
    mdt_data, cert_bytes = parse_mdt(open(args.path, "rb").read())
    with open(os.path.join(args.output_path, "report.json"), "w+") as f:
        f.write(json.dumps(mdt_data, indent=2))


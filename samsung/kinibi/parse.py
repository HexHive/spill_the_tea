#!/usr/bin/python3
import argparse
import sys
import os
import os.path
import re
import traceback
import json
import binascii

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512, SHA224, SHA384
from Crypto.PublicKey import RSA
from ta import TrustedApplication
from Crypto.Signature import pss
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def attemptVerify(message, crt, sig):
    # TEEGRIS uses one of these
    # https://globalplatform.org/wp-content/uploads/2020/10/GP-TEE-2020_01-CR-1.0_GP200007-Certificate-and-Certification-Report_20200922.pdf
    key = RSA.import_key(crt)
    hs = []
    hs.append(SHA224.new(message))
    hs.append(SHA384.new(message))
    hs.append(SHA256.new(message))
    hs.append(SHA512.new(message))
    for h in hs:
        try:
            pkcs1_15.new(key).verify(h, sig)
            print("Success")
            print(h)
            return True
        except (ValueError, TypeError):
            pass
        try:
            pss.new(key).verify(h, sig)
            print("Success PSS")
            print(h)
            return True
        except (ValueError, TypeError):
            pass
    return False

def verifySignature(message, crt, sig):
    key = RSA.import_key(crt)
    h = SHA256.new(message)
    try: # Works for SEC2
        pkcs1_15.new(key).verify(h, sig)
        print("Success")
        return True
    except (ValueError, TypeError):
        # print("Failed")
        pass
    try: # Works for SEC3
        pss.new(key).verify(h, sig)
        print("Success PSS")
        return True
    except (ValueError, TypeError):
        pass
    return False

def setup_args():
    """ Argument parser setup. """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--ta", action='store', dest='ta', required=True,
                       help='Path of the TA to analyze or folder of extracted TAs')
    parser.add_argument("-j", "--json-out", action='store', dest='out', default=None,
                       help='Path of the JSON report')
    return parser

def main():
    global decoded_crt

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if not os.path.exists(args.ta):
        print("No such file or directory", file=sys.stderr)
        sys.exit(1)

    if os.path.isfile(args.ta):
        analyze_ta(args.ta)
    elif os.path.isdir(args.ta):
        analyze_folder(args.ta, args.out)
    else:
        print("Invalid file", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

def analyze_folder(folderpath, outfile):
    ta_paths = [ os.path.join(x[0], y) for x in os.walk(folderpath) for y in x[2] if re.match("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", y) ]
    kinibi_ta_paths = [ os.path.join(x[0], y) for x in os.walk(folderpath) for y in x[2] if re.match("^[a-f0-9]{32}.tlbin$", y) ]
    ta_paths.extend(kinibi_ta_paths)

    print(ta_paths)
    reports = []
    for ta in ta_paths:
        try:
            j = analyze_ta(ta)
        except AssertionError as e:
            j = {
                "filename": ta,
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
        reports.append(j)

    if outfile is None:
        return

    with open(outfile, "w") as outfp:
        json.dump(reports, outfp)

def analyze_ta(tapath):
    report = {
        "filename": tapath,
        "success": True
    }
    f = open(tapath, "rb")

    ta = TrustedApplication(f)

    report["header_bytes"] = binascii.hexlify(ta.get_header()).decode(encoding="utf-8", errors="ignore")

    # Check if is a Kinibi (MCLF) image
    report["is_mclf_format"] = ta.get_header()[:4] == b"MCLF"

    if report["is_mclf_format"]:
        # extract the rollback version data for mclf
        f.seek(0)
        trustlet = f.read()
        report["rollback_version"] = int.from_bytes(trustlet[0x48:0x4c], "little")
        return report

    if (ta.validate_header() != True):
        return report

    hname = ta.human_name()
    report["human_name"] = hname.decode(encoding="utf-8", errors="ignore")

    secv = ta.sec_version()
    report["sec_version"] = secv

    ta.get_header()
    elf = ta.get_content_section()
    m = ta.get_metadata()[1:]

    if elf[-8:-4] == b"\x00\x00\x00\x04":
        print("[WARNING] SEC2 to SEC3 attack is possible on this TA!!!!")
        print("Last 8 bytes of ELF: ", elf[-8:])
    report["elf_last8"] = binascii.hexlify(elf[-8:]).decode(encoding="utf-8", errors="ignore")

    print(f"TA {hname} : SEC{secv}")
    if secv > 2:
        print(f"Rollback counters: {ta.rollback_version()}")
        report["rollback_version"] = ta.rollback_version()
    else:
        print("No rollback protection (SEC2)")
        report["rollback_version"] = None

    print("Metadata:", m)

    try:
        crt = ta.x509_cert()
        # print(ta.get_signature())
        sig = ta.get_signature()

        message = ta.get_signed_component()
        print(len(message))
        v = verifySignature(message, crt, sig)
        print(v)

        if not v:
            print("Unable to verify signature")
            report["signature_ok"] = False
            return report
        
        print("Signature verified")
        report["signature_ok"] = True

        print()
        print("TA certificate:")

        decoded_crt = x509.load_der_x509_certificate(crt, backend=default_backend())
        for ex in decoded_crt.extensions:
            print(ex)
        print("CRT fingerprint:", decoded_crt.fingerprint(hashes.SHA1()).hex())
        print()
        report["crt_fingerprint"] = decoded_crt.fingerprint(hashes.SHA1()).hex()
    except:
        pass

    return report

if __name__ == "__main__":
    main()

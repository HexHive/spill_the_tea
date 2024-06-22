#!/usr/bin/env python
import sys
import argparse
import os
import logging
import struct
import binascii

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

MCLF_MAGIC = b"MCLF"
EXPECTED_VERSIONS = [0x20005, 0x20004, 0x20003]


def u32(b):
    """ unpack u32 from b """
    return struct.unpack("<I", b)[0]


class MCLFUnknownVersionException(Exception):
    pass


def parse_header(idx, data):
    """
    typedef struct {
        uint32_t        magic;      /**< Header magic value ASCII "MCLF". */
        uint32_t        version;    /**< Version of the MCLF header structure. */
    } mclfIntro_t, *mclfIntro_ptr;
    """

    magic = data[idx:idx+4]
    version = u32(data[idx+4:idx+8])
    
    if version not in EXPECTED_VERSIONS:
        raise MCLFUnknownVersionException("Unexpected MCLF version {:x}@{:x}.".format(version, idx+4))


    flags = u32(data[idx+8:idx+12])
    mem_type = u32(data[idx+12:idx+16])
    service_type = u32(data[idx+16:idx+20])
    num_instances = u32(data[idx+20:idx+24])
    uuid = data[idx+24:idx+40]
    mc_driver_id = u32(data[idx+40:idx+44])

    text_start = u32(data[idx+48:idx+52])
    text_len = u32(data[idx+52:idx+56])
    
    data_start = u32(data[idx+60:idx+64])
    data_len = u32(data[idx+64:idx+68])

    bss_len = u32(data[idx+68:idx+72])
    entry = u32(data[idx+72:idx+76])
    service_version = u32(data[idx+76:idx+80])

    log.debug("Magic: {}".format(magic))
    log.debug("Version: {:x}".format(version))
    log.debug("Flags: {:x}".format(flags))
    log.debug("Mem type: {:x}".format(mem_type))
    log.debug("Service type: {:x}".format(service_type))
    log.debug("Num instances: {:x}".format(num_instances))
    # log.debug("UUID: {}".format(uuid.encode('hex')))
    log.debug("MC driver id: {}".format(mc_driver_id))
    log.debug("Text start: {:x}".format(text_start))
    log.debug("Text len: {:x}".format(text_len))
    log.debug("Data start: {:x}".format(data_start))
    log.debug("Data len: {:x}".format(data_len))
    log.debug("Bss len: {:x}".format(bss_len))
    log.debug("Entry: {:x}".format(entry))
    log.debug("Service version: {:x}".format(service_version))

    return uuid, text_len, data_len


def extract(sboot, outpath):
    """ extract mclf files from sboot

    parsing based on https://github.com/Trustonic/trustonic-tee-user-space/blob/master/common/MobiCore/inc/mcLoadFormat.
    """
    sboot.seek(0)
    data = sboot.read()

    # find first MCLF
    base = data.find(MCLF_MAGIC)
    while base != -1:

        try:
            uuid, text_len, data_len = parse_header(base, data)
        except MCLFUnknownVersionException as e:
            log.error(e)
            base = data.find(MCLF_MAGIC, base + len(MCLF_MAGIC))
            continue
        
        idx = base + 0x80

        version = u32(data[idx:idx+4])
        text_header_len = u32(data[idx+4:idx+8])
        required_features = u32(data[idx+8:idx+12])
        mclib_entry = u32(data[idx+12:idx+16])
        # skipping mclfIMD_t of size 8 + 4 = 12
        tl_api_version = u32(data[idx+28:idx+32])
        dr_api_version = u32(data[idx+32:idx+36])
        ta_properties = u32(data[idx+36:idx+40])

        log.debug("MCLF text header verison: {:x}".format(version))
        log.debug("Text header len: {:x}".format(text_header_len))
        log.debug("Required features: {:x}".format(required_features))

        out_file_path = os.path.join(outpath, "{}.tlbin".format(binascii.hexlify(uuid).decode()))
        with open(out_file_path, "wb") as f:
            f.write(data[base:base+text_len+data_len])

        base += text_len+data_len
        base = data.find(MCLF_MAGIC, base)


def setup_args():
    """ Argument parser setup. """
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--sboot", action="store", dest="sboot", help="Sboot image to extract mclf files from.")
    return parser


def main():
    """ This main method only invokes other methods according to the supplied args."""
    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.sboot:
        extract(args.sboot)
    else:
        arg_parser.print_help()
    sys.exit()


if __name__ == "__main__":
    main()

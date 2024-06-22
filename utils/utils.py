import subprocess
import logging
import io
import struct
from typing import List

TZAR_MAGIC = b"\x7f\xa5\x54\x41"
SPARSE_HEADER_MAGIC = b"\xED\x26\xFF\x3A"

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def find_files(where, what):
    cmd = ["find", where, "-iname", what, "-type", "f"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    d = p.stdout.read().decode("utf-8")
    p.wait()
    if not d:
        return []
    paths = [line for line in d.split("\n") if line]
    return paths


def get_subprocess(cmd):
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except OSError as e:
        log.error(e)
    return p


def system(cmd):
    p = get_subprocess(cmd)
    out, err = p.communicate()
    p.wait()
    return p.returncode, out, err


def kernel_from_bootimg(bimg: io.BytesIO) -> io.BytesIO:
    bimg.seek(8)
    kernel_size = bimg.read(4)
    kernel_size = int.from_bytes(kernel_size, "big")
    bimg.seek(0x800)
    return io.BytesIO(bimg.read(kernel_size))


def unpack_tzar(tzar: io.BytesIO) -> List[io.BytesIO]:
    magic = tzar.read(4)
    assert magic == TZAR_MAGIC

    hdr = tzar.read(12)
    (tzar_count, tzar_len, tzar_num_files) = struct.unpack("iii", hdr)

    extracted = []
    for _ in range(tzar_num_files):
        file_hdr = tzar.read(8)
        (fname_len, fdata_len) = struct.unpack("ii", file_hdr)
        fname = tzar.read(fname_len)
        fdata = tzar.read(fdata_len)

        fname = fname[0 : fname_len - 1]
        fname = fname.decode("utf-8")

        extracted.append((fname, io.BytesIO(fdata)))

    return extracted

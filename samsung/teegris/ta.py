import os
import re
import binascii

class TrustedApplication:
    def __init__(self, ta_file) -> None:
        self.ta_file = ta_file

    def validate_header(self) -> bool:
        f = self.ta_file
        f.seek(0)
        h = f.read( 8 + 4 ) # Read TEEGRIS header and ELF magic number
        if h[:3] != b"SEC":
            return False
        try:
            if int(h[3]) <= 4 and int(h[3]) >= 2:
                return False
        except ValueError:
            return False
        if int(h[3]) < 4 and h[8:12] != b"\x7FELF":
            return False
        return True

    def sec_version(self):
        if not self.validate_header():
            return None
        f = self.ta_file
        f.seek(3)
        v = f.read(1)
        try:
            v = int(v)
        except ValueError:
            return None
        return v
    
    def get_header(self):
        f = self.ta_file
        f.seek(0)
        return f.read(8)

    def get_content_section(self):
        f = self.ta_file
        f.seek(4)
        try:
            sl_b = f.read(4)
            section_length = int.from_bytes(sl_b, byteorder="big")
        except ValueError:
            return None
        return f.read(section_length)
    
    def rollback_version(self):
        m = self.get_metadata()
        v1, v2 = m[0:4], m[4:8]
        assert v1 == b"\x00\x00\x00\x04", "Wrong version length, should be 0x04"
        try:
            v2 = int.from_bytes(v2, byteorder="big")
        except ValueError:
            return None
        return v2

    def get_signed_component(self):
        f = self.ta_file
        secv = self.sec_version()
        content = self.get_content_section()
        if secv == 2:
            return content
        else:
            content += self.get_metadata()[:8]
            return content

    def get_metadata(self): # Samsung calls this field "CN"
        f = self.ta_file
        secv = self.sec_version() # Cache secv here to avoid later seeks on target file
        self.get_content_section()
        mdata = b""
        if secv > 2:
            mdata += f.read(8)
        mlen = f.read(1)
        mdata += mlen
        try:
            mlen = int.from_bytes(mlen, byteorder="big")
        except ValueError:
            return None
        tmp_mdata = f.read(mlen)
        assert(len(tmp_mdata) == mlen)
        mdata += tmp_mdata
        return mdata

    def get_signature(self):
        self.get_metadata()
        f = self.ta_file
        slen = f.read(2)
        try:
            slen = int.from_bytes(slen, byteorder="big")
        except ValueError:
            return None
        assert(slen == 0x100)
        return f.read( slen ) # 0x100

    def x509_cert(self):
        self.get_signature()
        f = self.ta_file
        clen = f.read(2)
        assert(len(clen) == 2)
        try:
            clen = int.from_bytes(clen, byteorder="big")
        except ValueError:
            return None
        cert = f.read(clen)
        assert(len(cert) == clen)
        assert( f.read() == b"" ) # If this check fails the format is broken and all the results are broken       
        return cert
        

    def human_name(self):
        fname = self.ta_file.name
        fname = os.path.basename(fname).lower()
        uuid = re.match("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", fname)
        try:
            uuid = uuid[0]
        except (AttributeError, IndexError):
            return None
        huuid = uuid.split("-")[-1]
        human_name = binascii.unhexlify(huuid)        
        human_name = human_name.replace(b"\x00", b" ").strip()
        return human_name
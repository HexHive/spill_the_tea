import os
import re
import sys

path = sys.argv[1]

for ta_file in os.listdir(path):
    if re.match(r'^.{8}-.{4}-.{4}-.{4}-.{12}$', ta_file):
        ta = open(os.path.join(path, ta_file),"rb").read()
        ta_elf = ta[8:]
        open(os.path.join(path, f"{ta_file}.elf"),"wb").write(ta_elf)
        print("writing ta to: ", os.path.join(path, f"{ta_file}.elf"))

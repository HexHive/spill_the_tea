from io import BufferedReader
import utils.ext4 as ext4
import os.path
import re

VERBOSE = True

# Usage: dump_folder(open("/tmp/test.img", "rb"), "system", "/tmp/test")

def dump_folder(
    img: BufferedReader, dump_path_str: str, dest: str, file_regex: str = None
) -> None:
    img.seek(0)

    if len(dump_path_str.strip()) == 0:
        dump_path = []
    else:
        dump_path = dump_path_str.split("/")
    v = ext4.Volume(img, offset=0)

    # Navigate the directory tree
    inode_obj = v.root
    for e in dump_path:
        inodes = [f[1] for f in inode_obj.open_dir() if f[0] == e]
        if len(inodes) == 0:
            raise FileNotFoundError
        assert len(inodes) == 1
        inode = inodes[0]
        inode_obj = v.get_inode(inode)

    # Create dest directory
    os.makedirs(os.path.join(dest, dump_path_str), exist_ok=True)

    if file_regex is not None:
        file_regex = [re.compile(x) for x in file_regex]

    # Dump everything in the subtree ( except symlinks )
    inode_queue = [(dump_path_str, inode_obj)]
    while len(inode_queue) > 0:
        inode_obj = inode_queue.pop()
        inodes = [
            (os.path.join(inode_obj[0], f[0]), v.get_inode(f[1]))
            for f in inode_obj[1].open_dir()
            if f[0] not in [".", ".."]
        ]
        inode_queue.extend([x for x in inodes if x[1].is_dir])

        # Create empty directories
        for x in inodes:
            if x[1].is_dir:
                if VERBOSE:
                    print(f"Creating dir { os.path.join( dest, x[0] )} ")
                os.mkdir(os.path.join(dest, x[0]))

        # Copy files
        file_inodes = [x for x in inodes if x[1].is_file]
        for f in file_inodes:
            if file_regex is not None:
                bname = os.path.basename(f[0])
                if not any([x.match(bname) for x in file_regex]):
                    if VERBOSE:
                        print(f"Skipping file { os.path.join( dest, f[0] )} ")
                    continue
            if VERBOSE:
                print(f"Copying file { os.path.join( dest, f[0] )} ")
            fo = open(os.path.join(dest, f[0]), "wb")
            fi = f[1].open_read()
            fo.write(fi.read())
            fo.close()

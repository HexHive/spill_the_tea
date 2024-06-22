# https://github.com/unix3dgforce/lpunpack/blob/master/lpunpack.py

import io
import sys
from pathlib import Path
from collections import namedtuple
from struct import unpack, calcsize

LP_PARTITION_RESERVED_BYTES = 4096
LP_METADATA_GEOMETRY_MAGIC = 0x616c4467
LP_METADATA_GEOMETRY_SIZE = 4096
LP_METADATA_HEADER_MAGIC = 0x414C5030
LP_SECTOR_SIZE = 512

class LpMetadataGeometry(object):
    """
        Offset 0: Magic signature
        Offset 4: Size of the LpMetadataGeometry
        Offset 8: SHA256 checksum
        Offset 40: Maximum amount of space a single copy of the metadata can use
        Offset 44: Number of copies of the metadata to keep
        Offset 48: Logical block size
    """
    def __init__(self, buffer):
        fmt = '<2I32s3I'
        (
            self.magic,
            self.struct_size,
            self.checksum,
            self.metadata_max_size,
            self.metadata_slot_count,
            self.logical_block_size

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataHeader(object):
    """
        +-----------------------------------------+
        | Header data - fixed size                |
        +-----------------------------------------+
        | Partition table - variable size         |
        +-----------------------------------------+
        | Partition table extents - variable size |
        +-----------------------------------------+
    """
    def __init__(self, buffer):
        fmt = '<I2hI32sI32s'
        (
            self.magic,
            self.major_version,
            self.minor_version,
            self.header_size,
            self.header_checksum,
            self.tables_size,
            self.tables_checksum

        ) = unpack(fmt, buffer[0:calcsize(fmt)])
        self.partitions = None
        self.extents = None
        self.groups = None
        self.block_devices = None


class LpMetadataTableDescriptor(object):
    def __init__(self, buffer):
        fmt = '<3I'
        (
            self.offset,
            self.num_entries,
            self.entry_size

        ) = unpack(fmt, buffer[:calcsize(fmt)])


class LpMetadataPartition(object):
    def __init__(self, buffer):
        fmt = '<36s4I'
        (
            self.name,
            self.attributes,
            self.first_extent_index,
            self.num_extents,
            self.group_index

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataExtent(object):
    def __init__(self, buffer):
        fmt = '<QIQI'
        (
            self.num_sectors,
            self.target_type,
            self.target_data,
            self.target_source

        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataPartitionGroup(object):
    def __init__(self, buffer):
        fmt = '<36sIQ'
        (
            self.name,
            self.flags,
            self.maximum_size
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class LpMetadataBlockDevice(object):
    def __init__(self, buffer):
        fmt = '<Q2IQ36sI'
        (
            self.first_logical_sector,
            self.alignment,
            self.alignment_offset,
            self.size,
            self.partition_name,
            self.flags
        ) = unpack(fmt, buffer[0:calcsize(fmt)])


class Metadata(object):
    def __init__(self):
        self.geometry = None
        self.partitions = []
        self.extents = []
        self.groups = []
        self.block_devices = []


class LpUnpackError(Exception):
    """Raised any error unpacking"""
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class LpUnpack(object):
    def __init__(self, fin, pname):
        self.partition_name = pname
        self.slot_num = None
        self.in_file_fd = fin

    def _ReadChunk(self, block_size):
        while True:
            data = self.in_file_fd.read(block_size)
            if not data:
                break
            yield data

    def ReadPrimaryGeometry(self):
        lpMetadataGeometry = LpMetadataGeometry(self.in_file_fd.read(LP_METADATA_GEOMETRY_SIZE))
        if lpMetadataGeometry is not None:
            return lpMetadataGeometry
        else:
            return self.ReadBackupGeometry()

    def ReadBackupGeometry(self):
        return LpMetadataGeometry(self.in_file_fd.read(LP_METADATA_GEOMETRY_SIZE))

    def GetPrimaryMetadataOffset(self, geometry, slot_number=0):
        return LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) + geometry.metadata_max_size * slot_number

    def GetBackupMetadataOffset(self, geometry, slot_number=0):
        start = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2) + \
                geometry.metadata_max_size * geometry.metadata_slot_count
        return start + geometry.metadata_max_size * slot_number

    def ParseHeaderMetadata(self, offsets):
        header = None
        for index, offset in enumerate(offsets):
            self.in_file_fd.seek(offset, 0)
            header = LpMetadataHeader(self.in_file_fd.read(80))
            header.partitions = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.extents = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.groups = LpMetadataTableDescriptor(self.in_file_fd.read(12))
            header.block_devices = LpMetadataTableDescriptor(self.in_file_fd.read(12))

            if header.magic != LP_METADATA_HEADER_MAGIC:
                if index + 1 > len(offsets):
                    raise LpUnpackError('Logical partition metadata has invalid magic value.')
                else:
                    print('Read Backup header by offset 0x{:x}'.format(offsets[index + 1]))
                    continue

            self.in_file_fd.seek(offset + header.header_size, 0)

        return header

    def ReadMetadata(self):
        metadata = Metadata()
        self.in_file_fd.seek(LP_PARTITION_RESERVED_BYTES, 0)
        metadata.geometry = self.ReadPrimaryGeometry()

        if metadata.geometry.magic != LP_METADATA_GEOMETRY_MAGIC:
            raise LpUnpackError('Logical partition metadata has invalid geometry magic signature.')

        if metadata.geometry.metadata_slot_count == 0:
            raise LpUnpackError('Logical partition metadata has invalid slot count.')

        if metadata.geometry.metadata_max_size % LP_SECTOR_SIZE != 0:
            raise LpUnpackError('Metadata max size is not sector-aligned.')

        offsets = [self.GetPrimaryMetadataOffset(metadata.geometry, slot_number=0), #self.slot_num
                   self.GetBackupMetadataOffset(metadata.geometry, slot_number=0)] #self.slot_num

        metadata.header = self.ParseHeaderMetadata(offsets)

        for index in range(0, metadata.header.partitions.num_entries):
            partition = LpMetadataPartition(self.in_file_fd.read(metadata.header.partitions.entry_size))
            partition.name = str(partition.name, 'utf-8').strip('\x00')
            metadata.partitions.append(partition)

        for index in range(0, metadata.header.extents.num_entries):
            metadata.extents.append(LpMetadataExtent(self.in_file_fd.read(metadata.header.extents.entry_size)))

        for index in range(0, metadata.header.groups.num_entries):
            group = LpMetadataPartitionGroup(self.in_file_fd.read(metadata.header.groups.entry_size))
            group.name = str(group.name, 'utf-8').strip('\x00')
            metadata.groups.append(group)

        for index in range(0, metadata.header.block_devices.num_entries):
            block_device = LpMetadataBlockDevice(self.in_file_fd.read(metadata.header.block_devices.entry_size))
            block_device.partition_name = str(block_device.partition_name, 'utf-8').strip('\x00')
            metadata.block_devices.append(block_device)

        try:
            super_device = metadata.block_devices[0]
            metadata_region = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE +
                                                             metadata.geometry.metadata_max_size *
                                                             metadata.geometry.metadata_slot_count) * 2
            if metadata_region > super_device.first_logical_sector * LP_SECTOR_SIZE:
                raise LpUnpackError('Logical partition metadata overlaps with logical partition contents.')
        except IndexError:
            raise LpUnpackError('Metadata does not specify a super device.')

        return metadata

    def ExtractPartition(self, meta):
        print('Extracting super partition [{}] ....'.format(meta.name), end='', flush=True)
        size = meta.size
        self.in_file_fd.seek(meta.offset)
        bio = io.BytesIO()
        for block in self._ReadChunk(meta.geometry.logical_block_size):
            if size == 0:
                break
            bio.write(block)
            size -= meta.geometry.logical_block_size
        print("[done]")
        return bio

    def Extract(self, partition, metadata):
        offset = 0
        size = 0

        unpack = namedtuple('Unpack', 'name offset size geometry')

        if partition.num_extents != 0:
            extent = metadata.extents[partition.first_extent_index]
            offset = extent.target_data * LP_SECTOR_SIZE
            size = extent.num_sectors * LP_SECTOR_SIZE

        return self.ExtractPartition(unpack(partition.name, offset, size, metadata.geometry))

    def unpack(self):
        self.in_file_fd.seek(0)
        metadata = self.ReadMetadata()

        if self.partition_name:
            filter_partition = None
            filter_extents = None
            for index, partition in enumerate(metadata.partitions):
                if partition.name in self.partition_name:
                    filter_partition = partition
            if not filter_partition:
                raise LpUnpackError('Could not find partition: {}'.format(self.partition_name))
            metadata.partitions = [ filter_partition ]
                
        for partition in metadata.partitions:
            return self.Extract(partition, metadata)
        return None
        
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Invalid usage")
        sys.exit(1)
    if not Path(sys.argv[1]).exists():
        print("File not found")
    with open(sys.argv[1], "rb") as fin:
        bio = LpUnpack(fin, "system").unpack()
    if bio == None:
        print("Partition name not found")
        sys.exit(0)
    with open(sys.argv[2], "wb") as fout:
        fout.write(bio.getbuffer()) 
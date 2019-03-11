import re
from io import BytesIO

from olefile.olefile import OleFileIO, STGTY_STREAM, OleDirectoryEntry
from pylnk.pylnk import Lnk, for_file, TypedPropertyValue, PropertyStore, ExtraData_PropertyStoreDataBlock, ExtraData
import struct


def read_custom(filename):
    link_header = b'\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    prefix = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    fileend = b'\xAB\xFB\xBF\xBA'
    with open(filename, 'rb') as f:
        custom = f.read()

    header = struct.unpack('<IIIII', custom[:20])
    count = header[4]

    matches = []
    for match in re.finditer(link_header, custom):
        # print(match)
        matches.append(match.start())

    print(len(matches), count)
    assert len(matches) == count

    matches.append(len(custom))
    for i in range(len(matches)-1):
        lnk_data = custom[matches[i]:matches[i+1]]
        if lnk_data.endswith(prefix):
            lnk_data = lnk_data[:-len(prefix)]
        if lnk_data.endswith(fileend):
            lnk_data = lnk_data[:-len(fileend)]
        # f = open(fn_prefix+str(i+1)+'.lnk','wb')
        # f.write(lnk_data)
        # f.close()
        try:
            # print(lnk_data)
            link = Lnk(BytesIO(lnk_data))
            print(link)
            # print('')
        except Exception as e:
            open('123.lnk','wb').write(lnk_data)
            print('parse error:', e)


def create_custom(filename, links):
    prefix = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
    fileend = b'\xAB\xFB\xBF\xBA'

    data = b''
    count = 0
    for link in links:
        name = link['name']
        app = link['path']
        workdir = link['workdir']
        arg = link['args']
        descr = link['descr']
        lnk = for_file(app, arguments=arg, description=descr, work_dir=workdir)

        v = TypedPropertyValue()
        v.set_string(name)
        store1 = PropertyStore(properties=[(2, v)],
                               format_id=b'\xE0\x85\x9F\xF2\xF9\x4F\x68\x10\xAB\x91\x08\x00\x2B\x27\xB3\xD9')
        v2 = TypedPropertyValue()
        v2.type = 0x48
        v2.value = b'\xe95\x0c\xd7\x16\xd7\x10K\x8aqD\x90\x8c\xd5\xd1$'
        store2 = PropertyStore(properties=[(104, v2)],
                               format_id=b'\xE0\x85\x9F\xF2\xF9\x4F\x68\x10\xAB\x91\x08\x00\x2B\x27\xB3\xD9')
        block = ExtraData_PropertyStoreDataBlock(stores=[store1, store2])
        extra = ExtraData(blocks=[block])
        lnk.extra_data = extra

        # lnk.save('tw2.lnk')

        lnk_stream = BytesIO()
        lnk.write(lnk_stream)
        lnk_data = lnk_stream.getvalue()
        data += prefix + lnk_data
        count += 1

    packed = struct.pack('<IIIII', 2, 1, 0, 2, count)
    packed += data
    packed += fileend
    open(filename, 'wb').write(packed)


def read_auto(filename):
    ole = OleFileIO(filename)
    names = list(zip(*ole.listdir()))[0]
    last_name = max([int(x, 16) for x in names if x != 'DestList'])
    next_name = last_name+1
    next_name_str = hex(next_name)[2:]

    destlist = ole.openstream('DestList').read()

    # header
    version, total, pinned, counter, last_id, actions_counter = struct.unpack('IIIIQQ', destlist[:32])
    # packed = struct.pack('IIIIQQ', version, total, pinned, counter, last_id, actions_counter)

    # entries
    print('\nDestList:')
    offset = 32
    for i in range(total):
        unknown_hash = struct.unpack('<Q', destlist[offset+0:offset+8])[0]
        new_vol_id = struct.unpack('<16B', destlist[offset+8:offset+24])
        new_obj_id = struct.unpack('<16B', destlist[offset+24:offset+40])
        # new_time = struct.unpack('<Q', destlist[offset+24:offset+32])[0]
        # new_seq = struct.unpack('>H', destlist[offset+32:offset+34])[0]
        # new_mac1, new_mac2 = struct.unpack('>LH', destlist[offset+34:offset+40])
        birth_vol_id = struct.unpack('<16B', destlist[offset+40:offset+56])
        birth_obj_id = struct.unpack('<16B', destlist[offset+56:offset+72])
        # birth_time = struct.unpack('<Q', destlist[offset+56:offset+64])[0]
        # birth_seq = struct.unpack('>H', destlist[offset+64:offset+66])[0]
        # birth_mac1, birth_mac2 = struct.unpack('>LH', destlist[offset+66:offset+72])
        netbios = struct.unpack('<16B', destlist[offset+72:offset+88])
        entry_id = struct.unpack('<L', destlist[offset+88:offset+92])[0]
        zeroes1 = struct.unpack('<Q', destlist[offset+92:offset+100])[0]
        last_access = struct.unpack('<Q', destlist[offset+100:offset+108])[0]
        pin_status = struct.unpack('<L', destlist[offset+108:offset+112])[0]
        ones1 = struct.unpack('<L', destlist[offset+112:offset+116])[0]
        access_count = struct.unpack('<L', destlist[offset+116:offset+120])[0]
        zeroes2 = struct.unpack('<Q', destlist[offset+120:offset+128])[0]
        length = struct.unpack('<H', destlist[offset+128:offset+130])[0]
        data = destlist[offset+130:offset+130+2*length]
        # zeroes3 = destlist[offset+130+2*length:offset+130+2*length+4]
        offset = offset + 130 + 2 * length + 4
        print(new_vol_id, new_obj_id, birth_vol_id, birth_obj_id, netbios, entry_id, last_access, pin_status, access_count, length, data)

    # links
    print('\nLinks:')
    for ole_stream in ole.listdir():
        ole_stream = ole_stream[0]
        link_io = ole.openstream(ole_stream)
        try:
            link = Lnk(link_io)
            print(link)
            print('')
        except:
            pass


def edit_auto(old_filename, new_filename, link_filename):
    ole = OleFileIO(old_filename)
    names = list(zip(*ole.listdir()))[0]
    last_name = max([int(x,16) for x in names if x != 'DestList'])
    next_name = last_name+1
    next_name_str = hex(next_name)[2:]

    destlist = ole.openstream('DestList').read()
    # header
    version, total, pinned, counter, last_id, actions_counter = struct.unpack('IIIIQQ', destlist[:32])
    packed = struct.pack('IIIIQQ', version, total, pinned, counter, last_id, actions_counter)
    # entries
    offset = 32
    for i in range(total):
        unknown_hash = struct.unpack('<Q', destlist[offset+0:offset+8])[0]
        new_vol_id = struct.unpack('<16B', destlist[offset+8:offset+24])
        new_obj_id = struct.unpack('<16B', destlist[offset+24:offset+40])
        # new_time = struct.unpack('<Q', destlist[offset+24:offset+32])[0]
        # new_seq = struct.unpack('>H', destlist[offset+32:offset+34])[0]
        # new_mac1, new_mac2 = struct.unpack('>LH', destlist[offset+34:offset+40])
        birth_vol_id = struct.unpack('<16B', destlist[offset+40:offset+56])
        birth_obj_id = struct.unpack('<16B', destlist[offset+56:offset+72])
        # birth_time = struct.unpack('<Q', destlist[offset+56:offset+64])[0]
        # birth_seq = struct.unpack('>H', destlist[offset+64:offset+66])[0]
        # birth_mac1, birth_mac2 = struct.unpack('>LH', destlist[offset+66:offset+72])
        netbios = struct.unpack('<16B', destlist[offset+72:offset+88])
        entry_id = struct.unpack('<L', destlist[offset+88:offset+92])[0]
        zeroes1 = struct.unpack('<Q', destlist[offset+92:offset+100])[0]
        last_access = struct.unpack('<Q', destlist[offset+100:offset+108])[0]
        pin_status = struct.unpack('<L', destlist[offset+108:offset+112])[0]
        ones1 = struct.unpack('<L', destlist[offset+112:offset+116])[0]
        access_count = struct.unpack('<L', destlist[offset+116:offset+120])[0]
        zeroes2 = struct.unpack('<Q', destlist[offset+120:offset+128])[0]
        length = struct.unpack('<H', destlist[offset+128:offset+130])[0]
        data = destlist[offset+130:offset+130+2*length]
        # zeroes3 = destlist[offset+130+2*length:offset+130+2*length+4]
        offset = offset + 130 + 2 * length + 4
        packed += struct.pack('<Q16B16B16B16B16BLQQLLLQH', unknown_hash,*new_vol_id,*new_obj_id,*birth_vol_id,
                              *birth_obj_id,*netbios,entry_id,zeroes1,last_access,pin_status,ones1,
                              access_count,zeroes2,length)
        packed += data
        packed += b'\x00'*4

        if entry_id == last_name:
            # new entry
            length = len(data) // 2

            # not checked by hash:
            #     ones1, access_count, zeroes2, length, data
            # checked by hash (entry invalid after any changes in this fields):
            #     unknown_hash, new_vol_id, new_obj_id, birth_vol_id, birth_obj_id,
            #     netbios, entry_id, zeroes1, last_access, pin_status,
            # so probably hash from offset+8 to offset+112 (one old source said it crc64, but first check failed)
            raise NotImplementedError
            unknown_hash = ...

            print(destlist[offset+0:offset+130])
            print("".join(["{:02x}".format(b) for b in destlist[offset+0:offset+8]]))
            packed += struct.pack('<Q16B16B16B16B16BLQQLLLQH', unknown_hash, *new_vol_id, *new_obj_id, *birth_vol_id,
                                  *birth_obj_id, *netbios, entry_id, zeroes1, last_access, pin_status, ones1,
                                  access_count, zeroes2, length)

            packed += data
            packed += b'\x00' * 4

        print(hex(entry_id), '\t', "".join(["{:02x}".format(b) for b in destlist[offset+0:offset+8]]))

    with open(link_filename, 'rb') as f:
        content = f.read()

    e = OleDirectoryEntry(entry={'sid': None,
                                 'name': next_name_str,
                                 'content': content,
                                 'entry_type': STGTY_STREAM,
                                 'isectStart': None,
                                 'dwUserFlags': 0,
                                 'createTime': 0,
                                 'modifyTime': 0,
                                 'sizeLow': 0,
                                 'sizeHigh': 0},
                          bare=True)
    ole.root.add_child(e)

    new_destlist = ole._find('DestList')

    # reset flag for read from content
    new_destlist.isectStart = None
    new_destlist.__dict__['content'] = packed

    ole.write_to_file(new_filename)


if __name__ == '__main__':
    # read_auto('./../test/f01b4d95cf55d32a.automaticDestinations-ms')
    read_custom(r'C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\590aee7bdd69b59b.customDestinations-ms')

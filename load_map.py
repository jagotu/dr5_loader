import idaapi
from idc import *

filename = AskFile(0, "", "Select MAP file")
if filename is None or not os.path.isfile(filename):
    exit()

real_base = {}
map_base = {}

real_base['DGROUP'] = idaapi.get_segm_base(idaapi.get_segm_by_name("DATA"))
real_base['IGROUP'] = idaapi.get_segm_base(idaapi.get_segm_by_name("TEXT"))

with open(filename, "r") as f:
    data = f.read().split('\n')
    
insection = None

for line in data:
    if line.strip() == 'Origin   Group':
        insection = "groups"
    elif line.strip() == 'Address         Publics by Value':
        insection = "publics_"
    elif line.strip() == '' and insection == "publics_":
        insection = "publics"
    elif line.strip() == '':
        insection = None
    else:
        if insection == "groups":
            (addr, name) = line.strip().split('   ')
            addr = addr.split(':')[0]
            map_base[addr] = name
        elif insection == "publics":
            (addr, name) = line.strip().split('       ')
            (base, off) = addr.split(':')
            if not base in map_base:
                print("Unkown section with base " + base)
                continue
            section_name = map_base[base]
            if(section_name in real_base):
                real_addr = real_base[section_name] + int(off, 16)
                idaapi.add_entry(real_addr, real_addr, name, 1)
            
            
        
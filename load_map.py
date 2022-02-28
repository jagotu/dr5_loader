import os
import ida_segment
import ida_kernwin
import ida_name

filename = ida_kernwin.ask_file(0, "", "FILTER *.MAP\nSelect MAP file")
if filename is not None and os.path.isfile(filename):

    real_base = {}
    map_base = {}

    real_base['DGROUP'] = ida_segment.get_segm_by_name("_DATA").start_ea
    real_base['IGROUP'] = ida_segment.get_segm_by_name("_TEXT").start_ea

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
                    #print("Unkown section with base " + base)
                    section_name = 'IGROUP' #pushpull hack
                else:
                    section_name = map_base[base]
                
                if(section_name in real_base):
                    real_addr = real_base[section_name] + int(off, 16)
                    ida_name.set_name(real_addr, name)
                
            

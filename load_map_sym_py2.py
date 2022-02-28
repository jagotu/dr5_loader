import os
import idaapi
import struct
import math

def getDat(start, length, whence):
  global sym_file
  sym_file.seek(start, whence)
  result = sym_file.read(length)
  return result

def getVal(start, length, whence):
  result = int(struct.unpack("<I", getDat(start, length, whence) + b"\00" * (4 - length))[0])
  return result

def toHex(decimal):
  return hex(decimal).split("x")[-1].upper()

def formatMap(_seg, addr, name, _special):
  global _entry
  _seg = str(toHex(_seg))
  addr = str(toHex(addr))
  if name.upper() == "__ASTART" or name.upper() == "WINSTART":
    _entry = "0" * (4 - len(_seg)) + _seg + ":" + "0" * (4 - len(addr)) + addr
  if _special is True:
    Abs = ["__ACRTUSED", "PLOCALHEAP", "PATOMTABLE",
           "PSTACKTOP", "PSTACKMIN", "PSTACKBOT",
           "PLOCALHEA2", "PATOMTABL2", "PSTACKMI2"]
    if name.upper() in Abs:
      _space = "  Abs  "
    else:
      _space = "  Imp  "
  else:
    _space = "       "
  return " " + "0" * (4 - len(_seg)) + _seg + ":" + "0" * (4 - len(addr)) + addr + _space + name

filename = idaapi.ask_file(0, "", "FILTER *.SYM *.MAP\nSelect MAP file")
if filename is not None and os.path.isfile(filename):

  if filename.endswith("SYM"):
    map_header = "\n Start     Length     Name                   Class\n 0000:0000 00000H     _TEXT                  CODE          ; placeholder\n 0000:0000 00000H     _DATA                  DATA          ; placeholder\n\n Origin   Group\n"
    map_origin = ""
    map_body = "\n  Address         Publics by Value\n"
    map_content = "\n"

    with open(filename, "rb") as sym_file:
      # ver_major = getVal(-1, 1, 2)
      # ver_minor = getVal(-2, 1, 2)
      ver = getVal(-2, 2, 2)
      if ver < 520 or ver > 778:
        idaapi.warning(".SYM version not supported! Output may be incorrect!")
      symLength = getVal(0, 4, 0)
      _realLength = os.path.getsize(filename) - 4
      if symLength == _realLength:
        _new = False
        _factor = 1
      else:
        _new = True
        _factor = 16
      entrySeg = getVal(4, 2, 0)
      _entry = "0" * (4 - len(toHex(entrySeg))) + toHex(entrySeg) + ":0000"
      numInHeader = getVal(6, 2, 0)
      # headSize = getVal(8, 2, 0)
      numSeg = getVal(10, 2, 0)
      segOne = getVal(12, 2, 0) * _factor
      # unknown = getVal(14, 1, 0)
      modNameLen = getVal(15, 1, 0)
      modName = getDat(16, modNameLen, 0)
      _count = 0
      _seg = 0
      _position = 16 + modNameLen + 1
      while _count < numInHeader:
        nameLen = getVal(_position + 2, 1, 0)
        map_content = map_content + formatMap(_seg, getVal(_position, 2, 0), getDat(_position + 3, nameLen, 0), True) + "\n"
        _position = _position + nameLen + 3
        _count = _count + 1
      _count = 0
      _position = segOne
      while _count < numSeg:
        _count2 = 0
        # nextSeg = getVal(_position, 2, 0) * _factor
        numName = getVal(_position + 2, 2, 0)
        # segLen = getVal(_position + 4, 2, 0)
        segNum = getVal(_position + 6, 2, 0)
        segNameLen = getVal(_position + 20, 1, 0)
        segName = getDat(_position + 21, segNameLen, 0)
        map_origin = map_origin + " " + "0" * (4 - len(toHex(segNum))) + toHex(segNum) + ":0   " + segName + "\n"
        _position = _position + 21 + segNameLen
        while _count2 < numName:
          nameLen = getVal(_position + 2, 1, 0)
          map_content = map_content + formatMap(segNum, getVal(_position, 2, 0), getDat(_position + 3, nameLen, 0), False) + "\n"
          _position = _position + nameLen + 3
          _count2 = _count2 + 1
        # _position = nextSeg
        if _new is True:
          _position = int(math.ceil((_position + numName * 2) / 16.0) * 16)
        else:
          _position = _position + numName * 2
        _count = _count + 1

    final_map = "\n\n " + modName + "\n" + map_header + map_origin + map_body + map_content + "\nProgram entry point at " + _entry + "\n"
    print final_map
    data = final_map.split('\n')

  else:
    with open(filename, "r") as f:
      data = f.read().split('\n')

  real_base = {}
  map_base = {}

  real_base['DGROUP'] = idaapi.get_segm_base(idaapi.get_segm_by_name("DATA"))
  real_base['IGROUP'] = idaapi.get_segm_base(idaapi.get_segm_by_name("TEXT"))
  real_base['_TEXT'] = idaapi.get_segm_base(idaapi.get_segm_by_name("TEXT"))    # just add _TEXT for now

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

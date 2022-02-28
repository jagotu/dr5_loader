#Very hackish code, but it seems to work for majority of DR5 binaries
#Written by JaGoTu
#https://github.com/jagotu/dr5_loader

import ida_entry
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_bytes
import ida_name
import ida_segment
import ida_segregs
import ida_struct
import os
import struct


NE_HEADER_MAGIC = b"NE"
MZ_HEADER_MAGIC = b"MZ"
SEG_STRUCT_SIZE = 12

segtable = {}
segimportstable = {}
importedmodules = {}
enttable = {}
toexport = []

def DB(f):
	return struct.unpack("<B", f.read(1))[0]
def DW(f):
	return struct.unpack("<H", f.read(2))[0]
def DD(f):
	return struct.unpack("<I", f.read(4))[0]

def nDB(ea, name):
	ida_bytes.create_data(ea, ida_bytes.FF_BYTE, 1, ida_idaapi.BADADDR)
	ida_name.set_name(ea, name, ida_name.SN_NOCHECK)
def nDW(ea, name):
	ida_bytes.create_data(ea, ida_bytes.FF_WORD, 2, ida_idaapi.BADADDR)
	ida_name.set_name(ea, name, ida_name.SN_NOCHECK)
def nDD(ea, name):
	ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)
	ida_name.set_name(ea, name, ida_name.SN_NOCHECK)

def rnDB(f, name, off):
	nDB(f.tell() - off, name)
	return DB(f)
def rnDW(f, name, off):
	nDW(f.tell() - off, name)
	return DW(f)
def rnDD(f, name, off):
	nDD(f.tell() - off, name)
	return DD(f)

def defSEGENT():
	sid = ida_struct.get_struc_id("SEGENT")
	if sid != ida_idaapi.BADADDR:
		struc = ida_struct.get_struc(sid)
		ida_struct.del_struc(struc)
	sid = ida_struct.add_struc(ida_idaapi.BADADDR, "SEGENT", 0)
	struc = ida_struct.get_struc(sid)

	ida_struct.add_struc_member(struc, "flags", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	ida_struct.add_struc_member(struc, "oSegment", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	ida_struct.add_struc_member(struc, "nParagraphs", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	ida_struct.add_struc_member(struc, "nReloc", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	ida_struct.add_struc_member(struc, "minAlloc", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	ida_struct.add_struc_member(struc, "unused", ida_idaapi.BADADDR, ida_bytes.FF_WORD, None, 2)
	return sid

def defENTENT():
	sid = ida_struct.get_struc_id("ENTENT")
	if sid != ida_idaapi.BADADDR:
		struc = ida_struct.get_struc(sid)
		ida_struct.del_struc(struc)
	sid = ida_struct.add_struc(ida_idaapi.BADADDR, "ENTENT", 0)
	struc = ida_struct.get_struc(sid)

	ida_struct.add_struc_member(struc, "flags", ida_idaapi.BADADDR, FF_BYTE, None, 1)
	ida_struct.add_struc_member(struc, "addr", ida_idaapi.BADADDR, FF_WORD, None, 2)
	return sid

def makePASSTR(ea):
	length = ida_bytes.get_byte(ea)
	ida_bytes.create_strlit(ea, length + 1, ida_bytes.STRTYPE_PASCAL)
	return length

def readPASSTR(ea):
	out = ""
	length = ida_bytes.get_byte(ea)
	ea += 1
	for i in range(length):
		out += chr(ida_bytes.get_byte(ea + i))
	return out

def readPASSTRF(f):
	length = f.read(1)[0]
	if length == 0:
		return ""
	else:
		return f.read(length).decode()

def make_entry(val, name):
	if val != 0:	
		segNo = (val >> 16) - 1
		segStart = segtable[segNo].start_ea
		segOff = (val & 0xFFFF)
		addr = segStart + segOff
		ida_entry.add_entry(addr, addr, name, 1)

def loadExportsF(f):
	f.seek(0)
	magic = f.read(2)
	if magic == MZ_HEADER_MAGIC:
		f.seek(0x22)
		MZlen = DW(f) * 16
		f.seek(MZlen)
		magic = f.read(2)

	if magic != NE_HEADER_MAGIC:
		return None

	headerStart = f.tell() - 2
	f.seek(headerStart + 0x34)
	cbNam = DW(f)
	pNam = DW(f)
	f.seek(headerStart + 0x3C)
	cbNRNam = DW(f)
	pNRNam = DW(f)

	table = {}

	f.seek(headerStart + pNam)
	while f.tell() < headerStart + pNam + cbNam:
		name = readPASSTRF(f)
		if len(name) == 0:
			DW(f)
			continue
		ordinal = DW(f)
		table[ordinal] = name

	f.seek(headerStart + pNRNam)
	while f.tell() < headerStart + pNRNam + cbNRNam:
		name = readPASSTRF(f)
		if len(name) == 0:
			DW(f)
			continue
		ordinal = DW(f)
		table[ordinal] = name

	return table

def loadExports(filename):
	with open(filename, "rb") as f:
		return loadExportsF(f)

def accept_file(f, filename):
	if filename == 0 or type(filename) == str:
		f.seek(0)
		magic = f.read(2)
		if magic == NE_HEADER_MAGIC:
				return "Plain New Executable (NE) DR5"

		if magic == MZ_HEADER_MAGIC:
			f.seek(0x22)
			MZlen = DW(f) * 16
			f.seek(MZlen)
			magic = f.read(2)
			if magic == NE_HEADER_MAGIC:
				return "New Executable (NE) DR5"

	return 0

def load_file(f, neflags, fileformatname):
	f.seek(0)	

	ida_idp.set_processor_type("metapc", ida_idp.SETPROC_LOADER)
	MGROUPStart = 0
	magic = f.read(2)

	if magic == MZ_HEADER_MAGIC:
		f.seek(0x22)
		MGROUPStart = DW(f) * 16
		f.seek(MGROUPStart)
		magic = f.read(2)

	headerSize = DW(f)
	segmentDataAlignment = DW(f)
	nextExeOff = DD(f)
	SegDataOff = DD(f)

	f.file2base(MGROUPStart, 0, SegDataOff, True)
	ida_segment.add_segm(0, 0, 0x50, "HEADER", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(0), 0)
	f.seek(MGROUPStart)

	magic = rnDW(f, "magic", MGROUPStart)
	headerSize = rnDW(f, "headerSize", MGROUPStart)
	segmentDataAlignment = rnDW(f, "segmentDataAlignment", MGROUPStart)
	nextExeOff = rnDD(f, "nextExeOff", MGROUPStart)
	SegDataOff = rnDD(f, "SegDataOff", MGROUPStart)

	ResDataOff = rnDD(f,"ResDataOff", MGROUPStart)
	flags = rnDW(f,"flags", MGROUPStart)
	version = rnDB(f,"version", MGROUPStart)
	revision = rnDB(f,"revision", MGROUPStart)
	AutoDataSegNo = rnDW(f,"AutoDataSegNo", MGROUPStart)
	HeapSize = rnDW(f,"HeapSize", MGROUPStart)
	StackSize = rnDW(f,"StackSize", MGROUPStart)
	StartProc = rnDD(f,"StartProc", MGROUPStart)
	LoadProc = rnDD(f,"LoadProc", MGROUPStart)
	FreeProc = rnDD(f,"FreeProc", MGROUPStart)
	nSegments = rnDW(f,"nSegments", MGROUPStart)
	pSegTable = rnDW(f,"pSegTable", MGROUPStart)
	cbResTab = rnDW(f,"cbResTab", MGROUPStart)
	pResTab = rnDW(f,"pResTab", MGROUPStart)
	cbEntTab = rnDW(f,"cbEntTab", MGROUPStart)
	pEntTab = rnDW(f,"pEntTab", MGROUPStart)
	cbNamTab = rnDW(f,"cbNamTab", MGROUPStart)
	pNamTab = rnDW(f,"pNamTab", MGROUPStart)
	cbStrTab = rnDW(f,"cbStrTab", MGROUPStart)
	pStrTab = rnDW(f,"pStrTab", MGROUPStart)
	cbNRNamTab = rnDW(f,"cbNRNamTab", MGROUPStart)
	pNRNamTab = rnDW(f,"pNRNamTab", MGROUPStart)

	ida_segment.add_segm(0, pSegTable, pSegTable + (nSegments * SEG_STRUCT_SIZE), "SEGTABLE", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pSegTable), 0)
	ida_segment.add_segm(0, pResTab, pResTab + cbResTab, "RESOURCES", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pResTab), 0)
	ida_segment.add_segm(0, pEntTab, pEntTab + cbEntTab, "ENTTABLE", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pEntTab), 0)
	ida_segment.add_segm(0, pNamTab, pNamTab + cbNamTab, "ENTNAME", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pNamTab), 0)
	ida_segment.add_segm(0, pStrTab, pStrTab + cbStrTab, "IMPORTS", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pStrTab), 0)
	ida_segment.add_segm(0, pNRNamTab, pNRNamTab + cbNRNamTab, "NRENTNAME", "MODULE")
	ida_segment.set_segm_addressing(ida_segment.getseg(pNRNamTab), 0)

	#parse segtable
	segentsid = defSEGENT()
	base = SegDataOff // 16

	importCount = 0
	for i in range(nSegments):
		segEntStart = pSegTable + i * SEG_STRUCT_SIZE
		ida_bytes.create_struct(segEntStart, SEG_STRUCT_SIZE, segentsid)
		segStart = ida_bytes.get_word(segEntStart + 2)
		segLen = ida_bytes.get_word(segEntStart + 4)
		segImports = ida_bytes.get_word(segEntStart + 6)
		importCount += segImports
		f.file2base(MGROUPStart + SegDataOff+segStart * 16, SegDataOff + segStart * 16, SegDataOff + (segStart + segLen) * 16, True)
		
		segBase = (base + segStart) * 16
		#segmentDef = ida_segment.segment_t()
		#segmentDef.start_ea = segBase
		#segmentDef.end_ea = (base + segStart + segLen) * 16
		#ida_segment.set_selector()
		print(base + segStart)
		ida_segment.add_segm(base + segStart, segBase, (base + segStart + segLen) * 16, "", "", 0) 
		sel = ida_segment.find_selector(base + segStart)
		seg = ida_segment.getseg(segBase)
		ida_segment.set_segm_addressing(seg, 0)
		segtable[i] = seg
		segimportstable[i] = segImports
		if i + 1 == AutoDataSegNo:
			ida_segment.set_segm_name(seg, "_DATA", 0)
			ida_segment.set_segm_class(seg, "DATA", 0)
			dataSel = sel
		else:
			ida_segment.set_segm_name(seg, "_TEXT", 0)
			ida_segment.set_segm_class(seg, "CODE", 0)
			if AutoDataSegNo == 0:
				dataSel = sel
	ida_segregs.set_default_dataseg(dataSel)

	#parse enttable
	pENT = pEntTab
	currord = 1
	while pENT < pEntTab + cbEntTab:
		bundleCount = ida_bytes.get_byte(pENT)
		bundleFlags = ida_bytes.get_byte(pENT + 1)
		if bundleCount == 0 and bundleFlags == 0:
			break
		pENT += 2
		for i in range(bundleCount):
			if bundleFlags == 0xFF:
				ordFlags = ida_bytes.get_byte(pENT)
				if ordFlags & 0x80:
					toexport.append(currord)
				segNo = ida_bytes.get_byte(pENT + 3)
				segOff = ida_bytes.get_word(pENT + 4)
			
				enttable[currord] = (segtable[segNo - 1].start_ea // 16, segOff)
				pENT += 6
			else:
				ordFlags = ida_bytes.get_byte(pENT)
				if ordFlags & 0x80:
					toexport.append(currord)
				segOff = ida_bytes.get_word(pENT + 1)
				enttable[currord] = (segtable[bundleFlags - 1].start_ea // 16, segOff)
				pENT += 3

			currord += 1

	modulename = readPASSTR(pNamTab)

	make_entry(StartProc, modulename.capitalize() + "Start")
	make_entry(LoadProc, modulename.capitalize() + "Load")
	make_entry(FreeProc, modulename.capitalize() + "Free")

	#export named ordinals
	namedordtable = loadExportsF(f)

	for i in toexport:
		if i in namedordtable:
			name = namedordtable[i]
		else:
			name = modulename + "_" + str(i)
		(base, off) = enttable[i]
		addr = base * 16 + off
		ida_entry.add_entry(i, addr, name, 1)

	#process imports

	ida_segment.add_segm(0xF000, 0xF0000, 0xF0000 + importCount * 2, "IMPORTS", "XTRN", 0)
	ida_segment.set_segm_addressing(ida_segment.getseg(0xF0000), 0)

	import_ea = 0xF0000

	for seg in segtable:
		segend = segtable[seg].end_ea
		f.seek(MGROUPStart + segend)
		
		for i in range(segimportstable[seg]):
			count = DB(f)
			mode = DB(f)
			relocStart = DW(f)
			module = DW(f)
			proc = DW(f)
			
			if(module == 0xFFFF):
				(base, off) = enttable[proc]
			else:
				modulestr = readPASSTR(pStrTab + module)
				if (proc & 0x8000) != 0: # read by ord
					ordinal = proc & 0x7FFF
					procname = modulestr + "_" + str(ordinal)
					if not modulestr in importedmodules:
						if os.path.isfile(modulestr + ".EXE"):
							importedmodules[modulestr] = loadExports(modulestr + ".EXE")
						else:
							filename = ida_kernwin.ask_file(0, modulestr + ".EXE", "Select file to name exports")
							if filename is not None and os.path.isfile(filename):
								importedmodules[modulestr] = loadExports(filename)
							else:
								importedmodules[modulestr] = None
					if modulestr in importedmodules and (importedmodules[modulestr] is not None) and ordinal in importedmodules[modulestr]:
						procname = importedmodules[modulestr][ordinal]
				else:
					procname = readPASSTR(pStrTab + proc)
				ida_bytes.create_data(import_ea, ida_bytes.FF_WORD, 2, ida_idaapi.BADADDR)
				ida_name.force_name(import_ea, procname)
				ida_bytes.set_cmt(import_ea, "Imported from " + modulestr, 1)
				base = 0xF000
				off = import_ea - 0xF0000
				import_ea += 2

			for xx in range(count):
				next = ida_bytes.get_word(segtable[seg].start_ea + relocStart)
				if mode == 0x20:
					ida_bytes.put_word(segtable[seg].start_ea + relocStart + 2, base)
					ida_bytes.put_word(segtable[seg].start_ea + relocStart, off)
				elif mode == 0x10:
					ida_bytes.put_word(segtable[seg].start_ea + relocStart, off)
				elif mode == 0x0:
					ida_bytes.put_word(segtable[seg].start_ea + relocStart, base)
				relocStart = next

			#print "import %d: seg %d mode %s count %d relocStart %s module %s proc %s" % (i, seg, hex(mode), count, hex(relocStart), modulestr, hex(proc))

	return 1

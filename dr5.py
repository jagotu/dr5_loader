#Very hackish code, but it seems to work for majority of DR5 binaries
#Written by JaGoTu
#https://github.com/jagotu/dr5_loader

import idaapi
import os
from idc import *

NE_HEADER_MAGIC 		= "NE"
MZ_HEADER_MAGIC         = "MZ"
SEG_STRUCT_SIZE			= 12

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
	MakeByte(ea)
	MakeName(ea,name)
def nDW(ea, name):
	MakeWord(ea)
	MakeName(ea,name)
def nDD(ea, name):
	MakeDword(ea)
	MakeName(ea,name)

def rnDB(f, name, off):
	nDB(f.tell()-off, name)
	return DB(f)
def rnDW(f, name, off):
	nDW(f.tell()-off, name)
	return DW(f)
def rnDD(f, name, off):
	nDD(f.tell()-off, name)
	return DD(f)

def defSEGENT():
	sid = GetStrucIdByName("SEGENT")
	if sid != -1:
		DelStruc(sid)
	sid = AddStrucEx(-1, "SEGENT", 0)
	AddStrucMember(sid, "flags", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "oSegment", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "nParagraphs", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "nReloc", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "minAlloc", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "unused", -1, FF_WORD, -1, 2)
	return sid

def defSEGENT():
	sid = GetStrucIdByName("SEGENT")
	if sid != -1:
		DelStruc(sid)
	sid = AddStrucEx(-1, "SEGENT", 0)
	AddStrucMember(sid, "flags", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "oSegment", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "nParagraphs", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "nReloc", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "minAlloc", -1, FF_WORD, -1, 2)
	AddStrucMember(sid, "unused", -1, FF_WORD, -1, 2)
	return sid

def defENTENT():
	sid = GetStrucIdByName("ENTENT")
	if sid != -1:
		DelStruc(sid)
	sid = AddStrucEx(-1, "ENTENT", 0)
	AddStrucMember(sid, "flags", -1, FF_BYTE, -1, 1)
	AddStrucMember(sid, "addr", -1, FF_WORD, -1, 2)
	return sid

def makePASSTR(ea):
	len = ida_bytes.get_byte(ea)
	ida_bytes.create_strlit(ea, len+1, STRTYPE_PASCAL)
	return len

def readPASSTR(ea):
	out = ""
	len = ida_bytes.get_byte(ea)
	ea += 1
	for i in range(len):
		out += chr(ida_bytes.get_byte(ea+i))
	return out

def readPASSTRF(f):
	out = ""
	len = ord(f.read(1)[0])
	return f.read(len)

def make_entry(val, name):
	if val != 0:	
		segNo = (val >> 16)-1
		segStart = segtable[segNo]
		segOff = (val & 0xFFFF)
		addr = segStart+segOff
		idaapi.add_entry(addr, addr, name, 1)

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
		ord = DW(f)
		table[ord] = name

	f.seek(headerStart + pNRNam)
	while f.tell() < headerStart + pNRNam + cbNRNam:
		name = readPASSTRF(f)
		if len(name) == 0:
			DW(f)
			continue
		ord = DW(f)
		table[ord] = name

	
	return table

def loadExports(filename):
	with open(filename, "rb") as f:
		return loadExportsF(f)





def accept_file(f, filename):
	if filename == 0 or type(filename) == str:
		f.seek(0)
		magic = f.read(2)
		if magic == NE_HEADER_MAGIC:
				return "Bare DR5 executable"

		if magic == MZ_HEADER_MAGIC:
			f.seek(0x22)
			MZlen = DW(f) * 16
			f.seek(MZlen)
			magic = f.read(2)
			if magic == NE_HEADER_MAGIC:
				return "DR5 executable"

	return 0

def load_file(f, neflags, format):
	f.seek(0)	

	idaapi.set_processor_type("metapc", SETPROC_ALL)
	MGROUPStart = 0
	magic = f.read(2)

	if magic == MZ_HEADER_MAGIC:
		f.seek(0x22)
		MGROUPStart = DW(f) * 16
		#f.file2base(0, 0, MGROUPStart, True)
		#idaapi.add_segm(0, 0, MGROUPStart, "MZStub", "MODULE")
		f.seek(MGROUPStart)
		magic = f.read(2)

	headerSize = DW(f)
	segmentDataAlignment = DW(f)
	nextExeOff = DD(f)
	SegDataOff = DD(f)

	f.file2base(MGROUPStart, 0, SegDataOff, True)
	idaapi.add_segm(0, 0, 0x50, "HEADER", "MODULE")
	f.seek(MGROUPStart+2)

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


	
	idaapi.add_segm(0, pSegTable, pSegTable+(nSegments*SEG_STRUCT_SIZE), "SEGTABLE", "MODULE")
	idaapi.add_segm(0, pResTab, pResTab+cbResTab, "RESOURCES", "MODULE")
	idaapi.add_segm(0, pEntTab, pEntTab+cbEntTab, "ENTTABLE", "MODULE")
	idaapi.add_segm(0, pNamTab, pNamTab+cbNamTab, "ENTNAME", "MODULE")	
	idaapi.add_segm(0, pStrTab, pStrTab+cbStrTab, "IMPORTS", "MODULE")	
	idaapi.add_segm(0, pNRNamTab, pNRNamTab+cbNRNamTab, "NRENTNAME", "MODULE")

	#parse segtable
	segentsid = defSEGENT()
	base = SegDataOff/16

	importCount = 0
	for i in range(nSegments):
		segEntStart = pSegTable+i*SEG_STRUCT_SIZE
		idaapi.doStruct(segEntStart, SEG_STRUCT_SIZE, segentsid)
		segStart = ida_bytes.get_word(segEntStart+2)
		segLen = ida_bytes.get_word(segEntStart+4)
		segImports = ida_bytes.get_word(segEntStart+6)
		importCount += segImports
		f.file2base(MGROUPStart+SegDataOff+segStart*16, SegDataOff+segStart*16, SegDataOff+(segStart+segLen)*16, True)
		
		segBase = (base + segStart)*16
		add_segm_ex(segBase, (base+segStart+segLen)*16, base + segStart, 0, segmentDataAlignment, 2, ADDSEG_NOSREG) 
		segtable[i] = segBase
		segimportstable[i] = segImports
		if i == 0:
			SegRename(segBase,"DATA")
			SegClass(segBase,"DATA")
			set_segm_type(segBase,SEG_DATA)
			dataBase = base+segStart
		else:
			SegRename(segBase,"TEXT")
			SegClass(segBase,"CODE")
			set_segm_type(segBase,SEG_CODE)
			SetSegmentAttr(segBase, SEGATTR_DS, dataBase)

	#parse enttable
	pENT = pEntTab
	currord = 1
	while pENT < pEntTab + cbEntTab:
		bundleCount = idaapi.get_byte(pENT)
		bundleFlags = idaapi.get_byte(pENT+1)
		if bundleCount == 0 and bundleFlags == 0:
			break
		pENT += 2
		for i in range(bundleCount):
			if bundleFlags == 0xFF:
				ordFlags = idaapi.get_byte(pENT)
				if ordFlags & 0x80:
					toexport.append(currord)
				segNo = idaapi.get_byte(pENT+3)
				segOff = idaapi.get_word(pENT+4)
			
				enttable[currord] = (segtable[segNo-1]/16, segOff)
				pENT += 6
			else:
				ordFlags = idaapi.get_byte(pENT)
				if ordFlags & 0x80:
					toexport.append(currord)
				segOff = idaapi.get_word(pENT+1)
				enttable[currord] = (segtable[bundleFlags-1]/16, segOff)
				pENT += 3

			currord += 1

	modulename = readPASSTR(pNamTab)

	make_entry(StartProc, modulename + "_start")
	make_entry(LoadProc, modulename + "_load")
	make_entry(FreeProc, modulename + "_free")

	#export named ordinals
	namedordtable = loadExportsF(f)

	for i in toexport:
		if i in namedordtable:
			name = namedordtable[i]
		else:
			name = "Ordinal" + str(i)
		(base, off) = enttable[i]
		addr = base*16+off
		idaapi.add_entry(i, addr, name, 1)


	#process imports

	idaapi.add_segm(0xF000, 0xF0000, 0xF0000 + importCount*2, "IMPORTS", "XTRN")

	import_ea = 0xF0000

	for seg in segtable:
		segend = SegEnd(segtable[seg])
		f.seek(MGROUPStart+segend)
		
		for i in range(segimportstable[seg]):
			count = DB(f)
			mode = DB(f)
			relocStart = DW(f)
			module = DW(f)
			proc = DW(f)
			
			if(module == 0xFFFF):
				(base, off) = enttable[proc]
			else:
				modulestr = readPASSTR(pStrTab+module)
				if (proc & 0x8000) != 0: # read by ord
					ordinal = proc & 0x7FFF
					procname = modulestr + "_Ordinal" + str(ordinal)
					if not modulestr in importedmodules:
						if os.path.isfile(modulestr + ".EXE"):
							importedmodules[modulestr] = loadExports(modulestr + ".EXE")
						else:
							filename = AskFile(0, modulestr + ".EXE", "Select file to name exports")
							if filename is not None and os.path.isfile(filename):
								importedmodules[modulestr] = loadExports(filename)
							else:
								importedmodules[modulestr] = None
					if modulestr in importedmodules and (importedmodules[modulestr] is not None) and ordinal in importedmodules[modulestr]:
						procname = importedmodules[modulestr][ordinal]
				else:
					procname = readPASSTR(pStrTab+proc)
				MakeWord(import_ea)
				idaapi.do_name_anyway(import_ea, procname)
				MakeRptCmt(import_ea, "Imported from " + modulestr)
				base = 0xF000
				off = import_ea - 0xF0000
				import_ea += 2

			for xx in range(count):
				next = idaapi.get_word(segtable[seg] + relocStart)
				if mode == 0x20:
					idaapi.put_word(segtable[seg] + relocStart+2, base)
					idaapi.put_word(segtable[seg] + relocStart, off)
				elif mode == 0x10:
					idaapi.put_word(segtable[seg] + relocStart, off)
				elif mode == 0x0:
					idaapi.put_word(segtable[seg] + relocStart, base)
				relocStart = next

				


			#print "import %d: seg %d mode %s count %d relocStart %s module %s proc %s" % (i, seg, hex(mode), count, hex(relocStart), modulestr, hex(proc))

	


	
	return 1
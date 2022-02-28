#Attempts to find & name callbacks registered with REGISTERCLASS
import ida_funcs
import ida_idaapi
import ida_name
import ida_offset
import ida_segment
import ida_ua
import ida_xref

res = ida_name.get_name_value(ida_idaapi.BADADDR, "REGISTERCLASS")
code_ea = ida_segment.get_segm_by_name("_TEXT").start_ea

procs = {
    0x18: "Create",
    0x1C: "Destroy",
    0x20: "Icon",
    0x24: "Paint",
    0x28: "Size",
    0x2C: "Input",
    0x30: "Focus",
    0x34: "Scroll",
    0x38: "Data",
    0x3C: "Help"
}

if res[0] == 1:
    regfunc = res[1]
    regcall = ida_xref.get_first_cref_to(regfunc)
    while regcall != ida_idaapi.BADADDR:
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, regcall)
        for i in range(20):
            if insn.get_canon_mnem() == 'mov' and insn.Op1.type == 4:
                if insn.Op1.addr in procs:
                    ida_offset.op_plain_offset(insn.ea, 1, code_ea)
                    target = code_ea + insn.Op2.value
                    ida_funcs.add_func(target, ida_idaapi.BADADDR)
                    ida_name.set_name(target, procs[insn.Op1.addr] + "_" + hex(regcall)[2:]) 
            ida_ua.decode_prev_insn(insn, insn.ea)
        regcall =  ida_xref.get_next_cref_to(regfunc, regcall)

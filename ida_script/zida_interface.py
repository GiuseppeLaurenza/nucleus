from idautils import *
from idaapi import *
import idc
import os
import json
import binascii
import mmap
import time
import ida_hexrays as hexray

#
#
#   This is an interface with ida it receives the parameters by ARGV it answers with the communication protocol
#   using mmap. Morevoer, when specified it dumps the data on a file. Otherwise the data protocol uses the
#   same mmap for communication protocol
#
#
# chiamo ida e uso IPC per far comunicare i processi
# SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#


ack_str = 'Good'
# to return in case of exception
nack_srt = 'Error'
# 4mb as communication buffer.
reply_message_size = 150000 * mmap.PAGESIZE
global memory_mapped_file



def getwritemmap(filename, size):
    try:
        fd = os.open(filename, os.O_RDWR)
        if os.name == 'nt':
            buffer = mmap.mmap(fd, size, access=mmap.ACCESS_WRITE)
        elif os.name == 'posix':
            buffer = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_WRITE)

        return (fd, buffer)
    except Exception as e:
        print(e)
        return None


def dumpfile(file, resp_data):
    with open(file) as f:
        json.dump(resp_data, f)


def respond(resp_object, byte_size):
    fd, buffer = getwritemmap(memory_mapped_file, byte_size)
    byte_json = str.encode(json.dumps(resp_object, separators=(',', ':')))
    buffer.write(byte_json)
    buffer.close()
    os.close(fd)


def get_function_list():
    functions = []
    for segment in Segments():
        for func_address in Functions(segment, SegEnd(segment)):
            function = {}
            function['name'] = GetFunctionName(func_address)
            function['address'] = func_address
            function['segment_name'] = SegName(func_address)
            functions.append(function)
    return functions



def function_hook(func):
    #implementa qui il tuo hook
    pass


def load_hex_ray():
    if not init_hexrays_plugin():
        idc.RunPlugin("hexx64", 0)
    if not init_hexrays_plugin():
        idc.RunPlugin("hexrays", 0)
    if not init_hexrays_plugin():
        idc.RunPlugin("hexarm", 0)

def install_hex_ray_hooks():
    if init_hexrays_plugin():

        def hexrays_event_callback(event, *args):
            if event == hxe_refresh_pseudocode:
                # We use this event instead of hxe_text_ready because
                #   MacOSX doesn't seem to work well with it
                # TODO: Look into this
                vu, = args
                function_hook(vu.cfunc)
            return 0

        install_hexrays_callback(hexrays_event_callback)
        print("installed hooks on hexray")
    else:
        print("There is no hexray decompiler")


def decompile_a_function(address):
    try:
        vfun=hexray.decompile(address)
        return str(vfun)
    except:
        return None


def ast_a_function(address):
    try:
        vfun=hexray.decompile(address)
        #without this print the vfun has an empty ctree associated.
        b=str(vfun)
        itemstruct={}
        #itemstruct['src']=b
        body=vfun.body
        str(body)
        treenodes=[x for x in vfun.treeitems]
        for x in treenodes:
            index=int(x.index)
            treeitem={}
            treeitem['op_name']=hexray.get_ctype_name(x.op)
            x=x.to_specific_type
            op=x.op
            if op == hexray.cot_call:
                #se e' una chiamata a funzione ci mettiamo il nome della funzione
               #treeitem['opcall']=idaapi.get_func_name(x.obj_ea)
                pass
            elif op == hexray.cot_ptr:
                pass
            elif op == hexray.cot_memptr:
                pass
            elif op == hexray.cot_memref:
                pass
            elif op == hexray.cot_obj:
                treeitem['name'] = idaapi.get_func_name(x.obj_ea)
            elif op == hexray.cot_var:
                treeitem['size'] = x.refwidth
                #treeitem['varname'] = str(dir(x))
                pass
            elif op == hexray.cot_num:
                #typeInfo = idaapi.tinfo_t()
                treeitem['value']=str(x.numval())

                #treeitem['size'] = x.refwidth
                #treeitem['formatname'] = str(x.n.nf.type_name)
                pass
            elif op == hexray.cot_helper:
                pass
            elif op == hexray.cot_str:
                pass

            try:
                treeitem['parent_index']=int(vfun.body.find_parent_of(x).index)
            except:
                treeitem['parent_index']=None

            itemstruct[index]=treeitem
        return itemstruct
    except Exception as e:
        return None



# return the call graph as a list of edges
def get_call_graph():
    functions = get_function_list()
    edges = []
    for f in functions:
        addr = f['address']
        calling_addr = set([first_func_chunk(x.frm) for x in XrefsTo(addr)])
        for c in calling_addr:
            edges.append((c, addr))
    return edges


def get_file_info():
    return get_file_type_name()


def get_imports():
    '''
    enumerate the imports of the currently loaded module.

    Yields:
      Tuple[int, str, str, int]:
        - address of import table pointer
        - name of imported library
        - name of imported function
        - ordinal of import
    '''
    for i in range(get_import_module_qty()):
        dllname = get_import_module_name(i)
        if not dllname:
            continue

        entries = []

        def cb(ea, name, ordinal):
            entries.append((ea, name, ordinal))
            return True  # continue enumeration

        enum_import_names(i, cb)

        for ea, name, ordinal in entries:
            yield ea, dllname, name, ordinal


def disassemble_func(address):
    func_dis = {}
    symbolic_calls = {}
    inst_num = 0
    flags = get_func_flags(address)
    last_addr = address
    asm = ''
    for addr in FuncItems(address):
        ins = DecodeInstruction(addr)
        # print('decoded')
        byte_instr = get_bytes(addr, ins.size)
        asm = asm + str(binascii.hexlify(byte_instr))
        inst_num = inst_num + 1
        last_addr = addr
        if idc.print_insn_mnem(addr) in ["call"]:
            # print('Call:'+str(ins))
            call_address = idc.get_operand_value(addr, 0)
            # print(call_address)
            start_addr = first_func_chunk(call_address)
            symbolic_calls[start_addr] = idc.get_func_name(call_address)

    func_dis['bytecode'] = asm
    func_dis['symbolic_calls'] = symbolic_calls
    func_dis['start_address'] = first_fusnc_chunk(address)
    func_dis['end_address'] = last_addr
    func_dis['segment_address'] = get_segm_start(address)
    func_dis['segment_name'] = SegName(address)
    func_dis['name'] = idc.get_func_name(address)
    func_dis['inst_numbers'] = inst_num
    # attenzione sta cosa ci da la roba riconosciuta con flirt.
    func_dis['library_flag'] = flags & FUNC_LIB
    return func_dis


def disassemble_functions(funcs_addresses):
    ret = []
    for segment in Segments():
        for address in Functions(segment, SegEnd(segment)):
            if address in funcs_addresses:
                # print('find_function')
                func = disassemble_func(address)
                ret.append(func)
    return ret

def decompile_functions(funcs_addresses):
    ret=[]
    for x in funcs_addresses:
        ret.append(decompile_a_function(x))
    return ret

def ast_functions(funcs_addresses):
    ret=[]
    for x in funcs_addresses:
        ret.append(ast_a_function(x))
    return ret

memory_mapped_file = str(idc.ARGV[1])
mode = str(idc.ARGV[2])
print('Mode:' + mode)

if mode == 'diss' or mode == 'decomp' or mode == 'ast':
    funcs_addresses = json.loads(idc.ARGV[3])
elif mode == 'dumpF':
    file_out = json.loads(idc.ARGV[3])

autoWait()
size = os.path.getsize(get_input_file_path())
reply_message_size = 10 * int(1 + size / mmap.PAGESIZE) * mmap.PAGESIZE


try:
    if mode == 'list':
        resp = (get_file_info(), get_function_list())
        respond(resp, reply_message_size)

    elif mode == 'diss':
        resp = (get_file_info(), disassemble_functions(funcs_addresses))
        respond(resp, reply_message_size)

    elif mode == 'decomp' or mode=='ast':
        print('loading hex_ray plugin for decompiling')
        load_hex_ray()
        if init_hexrays_plugin():
            if mode =='decomp':
                resp = (get_file_info(), decompile_functions(funcs_addresses))
            else:
                resp = (get_file_info(), ast_functions(funcs_addresses))
            respond(resp, reply_message_size)
        else:
            respond(nack_srt + ": No hexray plugin", reply_message_size)

    elif mode == 'all':
        f_list = [x['address'] for x in get_function_list()]
        resp = (get_file_info(), disassemble_functions(f_list))
        respond(resp, reply_message_size)
    elif mode == 'dumpF':
        f_list = [x['address'] for x in get_function_list()]
        resp = (get_file_info(), disassemble_functions(f_list))
        dumpfile(file_out, resp)
        respond(ack_str, reply_message_size)
    elif mode == 'callgraph':
        resp = (get_file_info(), get_call_graph())
        respond(resp, reply_message_size)

except Exception as e:
    respond(nack_srt + ":" + str(e), reply_message_size)
    print(e)
idc.Exit(0)

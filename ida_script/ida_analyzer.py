# chiamo ida e uso IPC per far comunicare i processi
# SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#

import os
import mmap
import tempfile
import subprocess
import uuid
import time
import json
from capstone import Cs
import capstone
import binascii
import puremagic
import hashlib
import traceback
import tqdm
import networkx as nx
# from matplotlib.pyplot import pause


script_path = 'zida_interface.py'


# crea un file pieno di null \0 di taglia size byte
def create_temp_file(filename, size):
    tmp_fold = tempfile.gettempdir()
    filename = os.path.join(tmp_fold, filename)
    try:
        file = open(filename, 'wb')
        buffer = str.encode('\0' * size)
        file.write(buffer)
        file.close()
    except Exception as e:
        print('Problem creating tempfile:' + tmp_fold)
        print(e)
    return filename


def get_read_mmap(filename, size):
    try:
        fd = os.open(filename, os.O_RDONLY)
        if os.name == 'nt':
            return (fd, mmap.mmap(fd, size, access=mmap.ACCESS_READ))
        elif os.name == 'posix':
            return (fd, mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ))
    except Exception as e:
        print(e)
        traceback.print_exc()
        return None


def filter_memory_references(i, symbols, API):
    inst = "" + i.mnemonic
    for op in i.operands:
        if (op.type == 1):
            inst = inst + " " + i.reg_name(op.reg)
        elif (op.type == 2):
            imm = int(op.imm)
            symbol = 'liavetevistiliavetevistisullerivedelfiume...INANIINANI'
            if str(imm) in symbols:
                symbol = str(symbols[str(imm)])
            if inst == 'call' and symbol in API:
                inst = inst + " " + symbol
            elif (-int(5000) <= imm <= int(5000)):
                inst = inst + " " + str(hex(op.imm))
            else:
                inst = inst + " " + str('HIMM')
        elif (op.type == 3):
            mem = op.mem
            if (mem.base == 0):
                r = "[" + "MEM" + "]"
            else:
                r = '[' + str(i.reg_name(mem.base)) + "*" + str(mem.scale) + "+" + str(mem.disp) + ']'
            inst = inst + " " + r
        if (len(i.operands) > 1):
            inst = inst + ","
    if "," in inst:
        inst = inst[:-1]
    inst = inst.replace(" ", "_")
    return str(inst)


def constantIndependt_hash(function1):
    string = ""
    for ins1 in function1:
        capstone_ins1 = ins1
        string = string + "<" + str(capstone_ins1.mnemonic)
        for op in capstone_ins1.operands:
            if (op.type == 1):
                # è un registro
                string = string + ";" + str(op.reg)
        string = string + ">"
    m = hashlib.sha256()
    m.update(string.encode('UTF-8'))
    return m.hexdigest()


def filter_asm_and_return_instruction_list(address, asm, symbols, arch, mode, API):
    binary = binascii.unhexlify(asm)
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    # md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == capstone.CS_ARCH_ARM:
        md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns = []
    cap_insns = []
    for i in md.disasm(binary, address):
        insns.append(filter_memory_references(i, symbols, API))
        cap_insns.append(i)
    del md
    return (constantIndependt_hash(cap_insns), insns)


class IDAFunctionAnalyzer:

    def __init__(self, filename, use_symbol, depth, library_symbols=None, file_dump=None):
        self.filename = '"'+os.path.abspath(filename)+'"'
        self.top_depth = depth
        self.use_symbol = use_symbol
        self.ida_script = os.path.abspath(script_path)
        self.ack_str = 'Good'
        # to return in case of exception
        self.nack_srt = 'Error'
        # size of the communication buffer - 4Mb
        size = os.path.getsize(filename)
        size = 10 * int(1 + size / mmap.PAGESIZE)
        self.size_buffer = size * mmap.PAGESIZE
        if 'IDA' in os.environ:
            self.idapath = os.environ['IDA']
        else:
            self.idapath = '/Applications/IDAPro7.0/idabin'

        print(self.idapath)
        if library_symbols != None:
            self.library_symbols = library_symbols
            self.__load_generic_API_sym(library_symbols)
        else:
            self.library_symbols = None
            self.api_sym = set([])

        if file_dump == None:
            self.file_dump = 'dump.json'
        else:
            self.file_dump = file_dump

        # timeout in seconds
        self.timeout_calling_ida = 60

    def __load_generic_API_sym(self, library_symbols):
        try:
            with open(library_symbols, 'r') as f:
                self.api_sym = set([x.rstrip() for x in f.readlines()])
        except:
            print('failed to load api symbols list... everything will be unnamed')
            self.api_sym = set([])

    def __load_libc_API_darwin(self, file):
        pass

    def __load_win32API_windows(self, file):
        pass

    def __load_libc_API_unix(self, file):
        try:
            with open(file, 'r') as f:
                self.api_sym = set([x.rstrip() for x in f.readlines()])
        except:
            print('failed to load api symbols list... everything will be unnamed')
            self.api_sym = set([])

    def __get_ida_exectuble(self):
        if os.name == 'nt':
            return '.\ida64.exe'
        elif os.name == 'posix':
            return './ida64'

    def __set_ARCH(self, info):
        info = info.upper()
        if 'X86' in info:
            self.arch = capstone.CS_ARCH_X86
            self.mode = capstone.CS_MODE_64

        elif '386' in info:
            self.arch = capstone.CS_ARCH_X86
            self.mode = capstone.CS_MODE_32

        elif 'ARM' in info:
            self.arch = capstone.CS_ARCH_ARM

        if 'ELF' in info and self.library_symbols == None:
            self.library_symbols = 'libc_unix'
            self.__load_libc_API_unix(self.library_symbols)

    def execute_ida(self, commands):
        ipcfilename = str(uuid.uuid4())
        if len(commands) == 1:
            commands.append('nop')

        # creo un file da 4mb per comunicare con ida
        ipcfilename = create_temp_file(ipcfilename, self.size_buffer)
        fd, buffer = get_read_mmap(ipcfilename, self.size_buffer)

        str_call = '{} -A -S"{} {} {} {}" {}'
        ida_executable = self.__get_ida_exectuble()
        command_list = [ida_executable, self.ida_script, ipcfilename]
        command_list.extend(commands)
        command_list.append(self.filename)

        formatted_call = str_call.format(*command_list)
        # print(formatted_call)
        idaprocess = subprocess.Popen(formatted_call, cwd=self.idapath, shell=True)

        for i in range(0, self.timeout_calling_ida):
            time.sleep(1)
            buffer.seek(0)
            string = (buffer.readline().rstrip(b'\x00'))
            if len(string) > 0:
                try:
                    ret = json.loads(string)
                except ValueError:
                    continue
                buffer.close()
                os.close(fd)
                os.remove(ipcfilename)
                #removing ida db
                #os.remove(os.path.join(os.path.dirname(self.filename), self.filename.split('.')[0] + str('.i64')))
                return ret
        idaprocess.kill()
        buffer.close()
        os.close(fd)
        os.remove(ipcfilename)
        #os.remove(os.path.join(os.path.dirname(self.filename),self.filename.split('.')[0]+str('.i64')))
        return []

    def __check_resp_and_return(self, response, error_msg):
        if self.nack_srt in response:
            print('error from:' + self.filename)
            print(error_msg)
        elif [] == response:
            print('timeout from:' + self.filename)
        else:
            info = response[0]
            self.__set_ARCH(info)
            response = response[1]
        return response

    def get_function_list(self):
        response_ida = self.execute_ida(['list'])
        list_funcs = self.__check_resp_and_return(response_ida, 'listing functions')
        return list_funcs

    def asm_functions_by_addresses(self, addresses):
        response_ida = self.execute_ida(['diss', str(json.dumps(addresses, separators=(',', ':')))])
        return self.__check_resp_and_return(response_ida, 'disassembling functions')

    def asm_functions_by_names(self, name):
        addresses = []
        for x in self.functions:
            if x['name'] == name:
                addresses.append(x['address'])
        return self.asm_functions_by_addresses(addresses)

    def __list_functions_to_disassembled(self, functions):
        ret = []
        for f in functions:
            # print((f,x))
            # print(f[1])
            address = f['start_address']
            symbols = f['symbolic_calls']
            bytecode = f['bytecode']
            symbols_clean = {}
            # TODO fix this unclen and unholly ugliness
            for key, value in symbols.items():
                symbols_clean[key] = value.replace('.', '')
            # print(symbols_clean)
            insns = filter_asm_and_return_instruction_list(address, bytecode, symbols_clean, self.arch, self.mode,
                                                           self.api_sym)
            ret.append(insns)
        return ret

    def disassemble_fun_by_addresses(self, addresses):
        lista = self.asm_functions_by_addresses(addresses)
        return self.__list_functions_to_disassembled(lista)

    def all(self):
        response_ida = self.execute_ida(['all'])
        return self.__check_resp_and_return(response_ida, 'getting all info')

    def disassemble_all(self):
        all = self.all()
        return self.__list_functions_to_disassembled(all)

    def disassemble_all_text(self):
        all = self.all()
        filtered = [x for x in all if x['segment_name'] == '.text']
        return self.__list_functions_to_disassembled(filtered)

    def get_call_graph(self):
        response_ida = self.execute_ida(['callgraph'])
        return self.__check_resp_and_return(response_ida, 'getting call graph')

    def decompile_fun_by_addresses(self,addresses):
        response_ida = self.execute_ida(['decomp', str(json.dumps(addresses, separators=(',', ':')))])
        return self.__check_resp_and_return(response_ida, 'decompiling functions')

    def ast_fun_by_addresses(self,addresses):
        response_ida = self.execute_ida(['ast', str(json.dumps(addresses, separators=(',', ':')))])
        return self.__check_resp_and_return(response_ida, 'asting functions')

    def analyze(self):
        ret = self.all()
        results = {}
        disassasm = self.__list_functions_to_disassembled(ret)
        for f, dis in zip(ret, disassasm):
            if self.use_symbol and f['segment_name'] != '.text':
                continue
            prepappend = 'X_' if self.arch == capstone.CS_ARCH_X86 else 'A_'
            inst = [prepappend + x for x in dis[1]]
            results[f['name']] = {'filtered_instructions': inst, "asm": f['bytecode'], "address": f['start_address']}
        return results

    def close(self):
        pass

    @staticmethod
    def ast_to_networkx(ast_dict):
        #print(ast_dict)
        graph=nx.DiGraph()
        for key,value in ast_dict.items():
            graph.add_node(int(key),**value)
        for key, value in ast_dict.items():
            #print(value)
            if value['parent_index'] is not None:
              graph.add_edge(value['parent_index'],int(key))
        return graph

def isELF(file):
    b = puremagic.magic_file(file)
    for x in b:
        if 'ELF' in x[-2]:
            return True


def disassemble_a_folder():
    # Disassemble all files in a folder and put the dump in dump.json
    folder_path = "C:\\Users\\massarelli\\Desktop\\dataset_x86"
    folder_path = os.path.abspath(folder_path)
    print(folder_path)
    only_elf = []
    if os.path.isdir(folder_path):
        only_elf = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if
                    os.path.isfile(os.path.join(folder_path, f)) and isELF(os.path.join(folder_path, f))]
        print(only_elf)

    for elf in tqdm.tqdm(only_elf):
        ida = IDAFunctionAnalyzer(elf, False, 1)
        info = ida.disassemble_all_text()
        with open("dump.json", "a") as myfile:
            json.dump(info, myfile)


if __name__ == '__main__':

    ida = IDAFunctionAnalyzer('/Users/giuseppe/Documents/Dati VM/PassaggioDati/qcow_copy/Windows/System32/ntdll.dll', False, 10)
    functions=ida.get_function_list()
    print(functions)
    #addresses=[f['address'] for f in functions]
    #print(f['name'])
    #for x in ida.ast_fun_by_addresses(addresses):
    #    if x is not None:
    #        G=IDAFunctionAnalyzer.ast_to_networkx(x)
    #        nx.draw(G, prog='dot')
    #        pause(1)

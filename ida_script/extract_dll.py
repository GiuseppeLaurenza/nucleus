import pefile
import sys
# import r2pipe
# import pandas as pd
import logging
from itertools import repeat
from multiprocessing import Pool, current_process
from os.path import exists
import subprocess
from ida_analyzer import IDAFunctionAnalyzer
import pandas as pd
SOURCE = None
DEST = None
LOGGER = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s')
LOGGER.setLevel(logging.INFO)


# def r2_analysis(sample_file_path):
#     r2 = r2pipe.open(sample_file_path,["-2"])
#     base = int(r2.cmd("?v $B"),16)
#     LOGGER.info(sample_file_path + " - aaa")
#     r2.cmd("aaa")
#     LOGGER.info(sample_file_path + " - aap")
#     r2.cmd("aap")
#     LOGGER.info(sample_file_path + " - aab")
#     r2.cmd("aab")
#     functions_df = pd.DataFrame(r2.cmdj("aflj"))
#     r2.quit()
#     return list(functions_df["offset"].subtract(base))

# def nucleus_pefile_analysis(sample_file_path):
#     pe = pefile.PE(sample_file_path)
#     base = pe.OPTIONAL_HEADER.ImageBase
#     list_address = []
#     try:
#         for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
#             list_address.append(exp.address)
#     except Exception as e:
#         LOGGER.info("Failed to parse export table")
#     pe.close()
#     cmd = ["/home/giuseppe/nucleus/nucleus", "-d", "linear", "-D", "-f", "-e", sample_file_path ]
#     process = subprocess.Popen(cmd,
#                            stdout=subprocess.PIPE,
#                            stderr=subprocess.PIPE)
#     # wait for the process to terminate
#     out, err = process.communicate()
#     errcode = process.returncode
#     nucleus_result = out.splitlines()
#     # print(len(nucleus_result))
#     for i in nucleus_result:
#         # print(i)
#         # print(i[0:18])
#         value = int(str(i)[2:20],16)
#         list_address.append(value-base)
#     set_address = set(list_address)
#     return set_address

def ida_script(sample_file_path):
    pe = pefile.PE(sample_file_path)
    base = pe.OPTIONAL_HEADER.ImageBase
    list_address = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            list_address.append(exp.address)
    except Exception as e:
        LOGGER.info("Failed to parse export table")
    pe.close()
    ida = IDAFunctionAnalyzer(sample_file_path, False, 10)
    functions = ida.get_function_list()
    functions_df = pd.DataFrame(functions)
    function_list_ida= list(functions_df["address"].subtract(base))
    list_address+=function_list_ida
    set_address = set(list_address)
    return set_address



def load_from_file(file_source=None, file_dest=None):
    if file_source is None:
        file_source = SOURCE
    LOGGER.info(str(current_process()) + ": Reading file " + file_source)
    try:
        # result = nucleus_pefile_analysis(file_source)
        result = ida_script(file_source)
        if file_dest is None:
            output_file = open(DEST,"w")
        else:
            output_file = open(file_dest,"w")
        for element in result:
            to_print = str(element)+"\n"
            output_file.write(to_print)
        output_file.close()
        LOGGER.info(str(current_process()) + ": Complete file "+ file_source)
    except Exception as e:
        LOGGER.info("Failed to open " + file_source)
        LOGGER.info(str(e))
        pass


def load_from_folder():
    print("Loading each file in folder " + SOURCE)

def parallel_load_from_file(base_folder, current_element):
        current_file = (current_element[(len(base_folder)+1):]).strip()
        # print(current_file)
        current_dest = DEST + (current_file.replace("/", "_")+".wl".lower())
        # print(current_dest)
        if not exists(current_dest):
            load_from_file(file_source=current_element.strip(), file_dest=current_dest) 

def load_from_list(base_folder):
    print("Reading list of file from: " + SOURCE + " with " + base_folder + " as base folder")
    with open(SOURCE) as f:
        file_list = f.readlines()
    for i in file_list:
        # current_file = (i[(len(base_folder) + 1):]).strip()
        current_file = (i[len(base_folder):]).strip()
        print(current_file)
        current_dest = (DEST + current_file.replace("/", "_")+".wl").lower()
        print(current_dest)
        load_from_file(file_source=i.strip(), file_dest=current_dest)

def parallel_load_from_list(base_folder):
    print("Reading list of file from: " + SOURCE + " with " + base_folder + " as base folder")
    with open(SOURCE) as f:
        file_list = f.readlines()
    pool = Pool(5)
    pool.starmap(parallel_load_from_file, zip(repeat(base_folder), file_list))
    

def main():
    argument_list = sys.argv
    global SOURCE
    global DEST
    if(len(argument_list) < 3 ):
        print("Missing arguments")
        print("USAGE")
        print("file/folder/list source destination [other args]")
        # SOURCE = "/home/giuseppe/qcow_copy/windows/system32/zipfldr.dll"
        # DEST = "/home/giuseppe/zipfldr.dll.out"
        # SOURCE = "/home/giuseppe/dll_list"
        # DEST = "/home/giuseppe/file_wl/"
        # base_folder = "qcow_copy"
        # SOURCE = "/home/giuseppe/list_dll"
        # DEST = "/home/giuseppe/PassaggioDati/file_wl_master/"
        # base_folder = "/mnt/qcow_mounted"


        SOURCE = "/Users/giuseppe/lista_dll"
        DEST = "/Users/giuseppe/file_wl/"
        base_folder = "/Users/giuseppe/Documents/Dati VM/PassaggioDati/qcow_copy/"
        load_from_list(base_folder)
        # parallel_load_from_list(base_folder)
        # SOURCE="/home/giuseppe/qcow_copy/windows/system32/kernelbase.dll"
        # DEST="/home/giuseppe/nucleus/prova.wl"
        # SOURCE="/Users/giuseppe/esent.dll"
        # SOURCE = "/Users/giuseppe/Documents/Dati VM/PassaggioDati/qcow_copy/Windows/System32/ntdll.dll"
        # load_from_file(SOURCE,DEST)
        # r2_analysis(SOURCE)
    else:
        function_type = sys.argv[1]
        SOURCE = sys.argv[2]
        DEST = sys.argv[3]
        if("folder" in function_type):
            load_from_folder()
        elif("function" in function_type):
            load_from_file()
        elif("list" in function_type):
            load_from_list(sys.argv[4])
        else:
            print("Unrecognized command: " + function_type)
main()
import pefile
import re

def parse_dll(dll_path):
    pe = pefile.PE(dll_path)
    symbols = []
    for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        symbol = entry.name.decode("utf-8")
        symbols.append(symbol)
    return symbols

def extract_dlls(assembly_code):
    dll_pattern = re.compile(r"([a-zA-Z0-9_]+\.dll)")
    dll_matches = dll_pattern.findall(assembly_code)
    return list(set(dll_matches))

def detect_architecture(assembly_code):
    if any(instr in assembly_code for instr in ["MOV", "ADD", "SUB", "CMP"]):
        if "ARM" in assembly_code:
            return "ARM"
        return "x86"
    elif any(instr in assembly_code for instr in ["add", "sub", "mov"]):
        return "MIPS"
    else:
        return "Unknown"

def parse_file_for_dlls(file_path):
    with open(file_path, "r") as file:
        assembly_code = file.read()
    return extract_dlls(assembly_code)

def parse_assembly_file(file_path):
    with open(file_path, "r") as file:
        assembly_code = file.read()
    architecture = detect_architecture(assembly_code)
    dll_symbols = extract_dlls(assembly_code)
    return architecture, dll_symbols

import os
import re
import pefile
import networkx as nx
import capstone
from utils import parse_dll, extract_dlls, detect_architecture, parse_file_for_dlls, parse_assembly_file

class StackTracker:
    def __init__(self):
        self.stack = []

    def push(self, value):
        self.stack.append(value)
    
    def pop(self):
        if self.stack:
            return self.stack.pop()
        return None

    def get_stack_state(self):
        return self.stack

class FunctionTracker:
    def __init__(self):
        self.call_stack = []

    def call(self, function_name):
        self.call_stack.append(function_name)

    def ret(self):
        if self.call_stack:
            self.call_stack.pop()

    def get_current_function(self):
        if self.call_stack:
            return self.call_stack[-1]
        return None

class ControlFlowTracker:
    def __init__(self):
        self.branches = []

    def add_jump(self, label):
        self.branches.append(f"Jump to {label}")

    def add_condition(self, condition, label):
        self.branches.append(f"Condition {condition} -> {label}")

    def get_branches(self):
        return self.branches

class ControlFlowGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_edge(self, from_node, to_node):
        self.graph.add_edge(from_node, to_node)

    def get_graph(self):
        return self.graph

def parse_arm_instruction(instruction):
    arm_instructions = {
        "MOV": "Move data",
        "ADD": "Add values",
        "SUB": "Subtract values",
        "CMP": "Compare values",
        "B": "Branch (jump)",
        "BL": "Branch and link (function call)"
    }

    match = re.match(r"^(MOV|ADD|SUB|CMP|B|BL)\s+(.+)", instruction)
    if match:
        instr = match.group(1)
        operands = match.group(2).strip().split(',')
        if instr in arm_instructions:
            return {"instruction": arm_instructions[instr], "operands": operands}
    return None

def parse_mips_instruction(instruction):
    mips_instructions = {
        "add": "Add values",
        "sub": "Subtract values",
        "mov": "Move data",
        "bne": "Branch if not equal",
        "j": "Jump"
    }

    match = re.match(r"^(add|sub|mov|bne|j)\s+(.+)", instruction)
    if match:
        instr = match.group(1)
        operands = match.group(2).strip().split(',')
        if instr in mips_instructions:
            return {"instruction": mips_instructions[instr], "operands": operands}
    return None

def analyze_instruction(instruction):
    return {"instruction": instruction, "operands": []}

def parse_architecture_specific(assembly_code, architecture):
    instructions = []
    for line in assembly_code.strip().splitlines():
        line = line.strip()
        if architecture == "ARM":
            parsed = parse_arm_instruction(line)
        elif architecture == "MIPS":
            parsed = parse_mips_instruction(line)
        else:
            parsed = analyze_instruction(line)

        if parsed:
            instructions.append(parsed)
    return instructions

def handle_stack_operations(instruction, stack_tracker):
    if "push" in instruction:
        value = instruction.split()[1]
        stack_tracker.push(value)
    elif "pop" in instruction:
        stack_tracker.pop()

def handle_function_calls(instruction, function_tracker):
    if "call" in instruction:
        function_name = instruction.split()[1]
        function_tracker.call(function_name)
    elif "ret" in instruction:
        function_tracker.ret()

def handle_control_flow(instruction, control_flow_tracker):
    if "jmp" in instruction:
        label = instruction.split()[1]
        control_flow_tracker.add_jump(label)
    elif "je" in instruction or "jne" in instruction:
        condition = instruction.split()[0]
        label = instruction.split()[1]
        control_flow_tracker.add_condition(condition, label)

def handle_pseudo_operations(instruction):
    if instruction.startswith(".data"):
        print("Entering data section")
    elif instruction.startswith(".text"):
        print("Entering text section")
    elif instruction.startswith(".global"):
        symbol = instruction.split()[1]
        print(f"Declaring global symbol: {symbol}")

def parse_dll_libraries(assembly_code):
    dlls = extract_dlls(assembly_code)
    all_symbols = []
    for dll in dlls:
        symbols = parse_dll(dll)
        all_symbols.extend(symbols)
    return all_symbols

def disassemble_exe(exe_path):
    pe = pefile.PE(exe_path)
    code = b""
    for section in pe.sections:
        if section.Name.decode().strip() == ".text":
            code += section.get_data()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instructions = []
    for insn in md.disasm(code, 0x1000):
        instructions.append(f"{insn.mnemonic} {insn.op_str}")

    return "\n".join(instructions)

def parse_assembly_file(file_path):
    with open(file_path, "r") as f:
        assembly_code = f.read()

    architecture = detect_architecture(assembly_code)
    instructions = parse_architecture_specific(assembly_code, architecture)

    stack_tracker = StackTracker()
    function_tracker = FunctionTracker()
    control_flow_tracker = ControlFlowTracker()

    for instruction in instructions:
        handle_stack_operations(instruction["instruction"], stack_tracker)
        handle_function_calls(instruction["instruction"], function_tracker)
        handle_control_flow(instruction["instruction"], control_flow_tracker)
        handle_pseudo_operations(instruction["instruction"])

    dll_symbols = parse_dll_libraries(assembly_code)

    return instructions, dll_symbols, architecture

def main():
    print("Do you want to disassemble an EXE or provide an already disassembled assembly file?")
    choice = input("Enter '1' to disassemble EXE or '2' to provide assembly code file: ")

    if choice == "1":
        exe_path = input("Enter the path to the EXE file: ")
        if not os.path.exists(exe_path):
            print("The EXE file does not exist.")
            return

        disassembled_code = disassemble_exe(exe_path)
        with open("disassembled_output.txt", "w") as f:
            f.write(disassembled_code)
        print(f"Disassembly complete. Saved to 'disassembled_output.txt'.")

        file_path = "disassembled_output.txt"
    elif choice == "2":
        file_path = input("Enter the path to the assembly code file: ")
        if not os.path.exists(file_path):
            print("The file does not exist.")
            return
    else:
        print("Invalid choice.")
        return

    instructions, dll_symbols, architecture = parse_assembly_file(file_path)
    print(f"Parsed Instructions: {instructions}")
    print(f"DLL Symbols: {dll_symbols}")
    print(f"Detected Architecture: {architecture}")

if __name__ == "__main__":
    main()

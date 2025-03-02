import re
import pefile
import networkx as nx

# ============================
# Stack Tracker Class
# ============================
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

# ============================
# Function Tracker Class
# ============================
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

# ============================
# Control Flow Tracker Class
# ============================
class ControlFlowTracker:
    def __init__(self):
        self.branches = []

    def add_jump(self, label):
        self.branches.append(f"Jump to {label}")

    def add_condition(self, condition, label):
        self.branches.append(f"Condition {condition} -> {label}")

    def get_branches(self):
        return self.branches

# ============================
# Control Flow Graph Class
# ============================
class ControlFlowGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_edge(self, from_node, to_node):
        self.graph.add_edge(from_node, to_node)

    def get_graph(self):
        return self.graph

# ============================
# DLL Parsing Utility
# ============================
def parse_dll(dll_path):
    pe = pefile.PE(dll_path)
    symbols = []
    for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        symbol = entry.name.decode("utf-8")
        symbols.append(symbol)
    return symbols

# ============================
# ARM Instruction Handler
# ============================
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

# ============================
# MIPS Instruction Handler
# ============================
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

# ============================
# Main Parser Logic
# ============================
def parse_architecture_specific(assembly_code, architecture):
    instructions = []
    for line in assembly_code.strip().splitlines():
        line = line.strip()
        if architecture == "ARM":
            parsed = parse_arm_instruction(line)
        elif architecture == "MIPS":
            parsed = parse_mips_instruction(line)
        else:
            parsed = analyze_instruction(line)  # Default to x86

        if parsed:
            instructions.append(parsed)
    return instructions

def analyze_instruction(instruction):
    # Placeholder for x86-specific parsing
    return {"instruction": instruction, "operands": []}

# ============================
# Stack, Function Calls, Control Flow Handlers
# ============================
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

# ============================
# DLL Handling
# ============================
def parse_dll_libraries(assembly_code):
    dlls = extract_dlls(assembly_code)  # Extract DLL paths from code or symbols
    all_symbols = []
    for dll in dlls:
        symbols = parse_dll(dll)
        all_symbols.extend(symbols)
    return all_symbols

def extract_dlls(assembly_code):
    # Example function to detect and extract DLLs from assembly code
    return ["kernel32.dll", "user32.dll"]

# ============================
# Main Assembly Parsing
# ============================
def parse_assembly_file(file_path):
    with open(file_path, "r") as f:
        assembly_code = f.read()

    # Parse the assembly code based on its architecture (detect it from code or manually set)
    architecture = "x86"  # Can be ARM, MIPS, or x86, for example
    instructions = parse_architecture_specific(assembly_code, architecture)

    # Create trackers for stack, function calls, and control flow
    stack_tracker = StackTracker()
    function_tracker = FunctionTracker()
    control_flow_tracker = ControlFlowTracker()

    # Process instructions
    for instruction in instructions:
        handle_stack_operations(instruction["instruction"], stack_tracker)
        handle_function_calls(instruction["instruction"], function_tracker)
        handle_control_flow(instruction["instruction"], control_flow_tracker)
        handle_pseudo_operations(instruction["instruction"])

    # Optionally, handle DLL libraries
    dll_symbols = parse_dll_libraries(assembly_code)

    return instructions, dll_symbols

# Example usage
if __name__ == "__main__":
    file_path = "example.asm"
    instructions, dll_symbols = parse_assembly_file(file_path)
    print("Parsed Instructions:", instructions)
    print("DLL Symbols:", dll_symbols)

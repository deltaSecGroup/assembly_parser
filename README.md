# Assembly Parser

This project provides a Python-based script for parsing assembly code from a disassembled executable (EXE) file or an already provided assembly code in `.txt` format. It also includes features like detecting the architecture (x86, ARM, MIPS), tracking stack operations, handling function calls, and control flow instructions, and parsing DLL symbols. Parsed instructions are saved to a randomly named `.txt` file for easy reference.

## Features

- **Disassemble EXE Files**: If you provide an EXE file, the script can disassemble it and extract the assembly code.
- **Assembly Code Parsing**: Parse assembly instructions and analyze them based on the architecture (x86, ARM, or MIPS).
- **Track Stack Operations**: The script can detect `push` and `pop` instructions and track the stack's state.
- **Function Call Tracking**: It tracks function calls (`call`, `ret`) and provides insights into the call stack.
- **Control Flow Tracking**: Handles control flow instructions like `jmp`, `je`, `jne`, etc., and tracks branches.
- **DLL Symbol Extraction**: Identifies and parses DLL libraries used in the assembly code.
- **Random Filename for Saved Output**: Parsed instructions are saved in a `.txt` file with a randomly generated name (`parsed_<random>.txt`).

## Requirements

To run this script, you'll need the following Python dependencies:

- `capstone`: A disassembler framework.
- `pefile`: A library to work with PE files (used for disassembling EXE files).
- `networkx`: A graph library used for control flow analysis.
- `random` and `string`: Python's built-in modules for generating random filenames.

You can install the necessary dependencies using pip:

```bash
pip install capstone pefile networkx
```

## Usage

### Step 1: Choose Whether to Disassemble an EXE or Use an Existing Assembly File

When you run the script, you will be prompted to choose:

1. **Disassemble EXE**: If you have an EXE file, the script will disassemble it and save the assembly code in a `.txt` file.
2. **Provide Assembly File**: If you already have a disassembled assembly code in a `.txt` file, you can provide its path, and the script will parse it.

### Step 2: Running the Script

To run the script, simply execute it:

```bash
python assembly_parser.py
```

### Example Output

1. **Disassembling EXE**:

```bash
Do you want to disassemble an EXE or provide an already disassembled assembly file?
Enter '1' to disassemble EXE or '2' to provide assembly code file: 1
Enter the path to the EXE file: example.exe
Disassembly complete. Saved to 'disassembled_output.txt'.
Parsed Instructions: [{'instruction': 'MOV', 'operands': ['eax, 0x4']}, {'instruction': 'ADD', 'operands': ['ebx, eax']}, ...]
DLL Symbols: ['kernel32.dll', 'user32.dll']
Detected Architecture: x86
Parsed instructions saved to: parsed_h9Xz5v6Q.txt
```

2. **Providing Assembly Code File**:

```bash
Do you want to disassemble an EXE or provide an already disassembled assembly file?
Enter '1' to disassemble EXE or '2' to provide assembly code file: 2
Enter the path to the assembly code file: example.asm
Parsed Instructions: [{'instruction': 'MOV', 'operands': ['eax, 0x4']}, {'instruction': 'ADD', 'operands': ['ebx, eax']}, ...]
DLL Symbols: ['kernel32.dll', 'user32.dll']
Detected Architecture: x86
Parsed instructions saved to: parsed_x2Jk9M7B.txt
```

### Output File

The parsed instructions will be saved in a file named `parsed_<random_string>.txt`, where `<random_string>` is a randomly generated alphanumeric string. The file will contain the assembly instructions parsed by the script.

### Example of Parsed Instructions in Output File:

```text
MOV eax, 0x4
ADD ebx, eax
PUSH ebx
POP eax
CALL my_function
```

### Additional Features

- **Stack Operations**: The script tracks stack operations (`push`, `pop`) and the stack state.
- **Function Calls**: Function calls (`call`, `ret`) are tracked, and the current function in the call stack is maintained.
- **Control Flow**: Handles control flow instructions like `jmp`, `je`, `jne`, `loop`, and more.
- **DLL Libraries**: The script extracts and parses DLL libraries used in the assembly code.

## File Structure

The project consists of the following files:

```
assembly_parser.py      # Main script for disassembling and parsing assembly code
utils.py               # Utility functions for parsing DLLs and extracting symbols
README.md              # This README file
```

## License

This project is open-source and available under the MIT License.

## Troubleshooting

If you encounter any issues:

1. Ensure all dependencies are installed correctly (`capstone`, `pefile`, `networkx`).
2. Check that the EXE file exists if you're using the disassembly option.
3. If the assembly code file is malformed or empty, the script may fail to parse it correctly.

Feel free to open an issue on the [GitHub repository](https://github.com/deltaSecGroup/assembly_parser) if you need help or have any questions.

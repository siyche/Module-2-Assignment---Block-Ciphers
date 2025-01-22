from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import numpy as np

# RSA Performance Data (Operations per second)
rsa_keys = [512, 1024, 2048, 3072, 4096, 7680, 15360]
rsa_signing = [52741.1, 10925.4, 1709.5, 611.0, 279.7, 33.7, 6.4]
rsa_verifying = [540700.9, 219319.7, 69324.0, 33145.8, 19257.8, 5669.6, 1441.0]
rsa_encrypting = [487216.1, 206335.5, 66100.8, 32612.9, 19033.4, 5574.9, 1437.7]
rsa_decrypting = [42666.7, 9816.9, 1749.5, 613.5, 277.6, 33.8, 6.4]

# AES Performance Data (Throughput in MB/s)
aes_block_sizes = [16, 64, 256, 1024, 8192, 16384]
aes_128_throughput = [1099586.82, 1440501.32, 1536528.03, 1565479.82, 1588978.60, 1575107.18]
aes_192_throughput = [1013839.49, 1282349.40, 1281672.96, 1285703.51, 1310451.50, 1302386.01]
aes_256_throughput = [641456.45, 1050208.88, 1102578.60, 1115866.89, 1126180.82, 1128890.37]

# Plot RSA performance
plt.figure(figsize=(14, 6))

# RSA Performance Subplot
plt.subplot(1, 2, 1)
plt.plot(rsa_keys, rsa_signing, marker='o', label='Signing (ops/sec)')
plt.plot(rsa_keys, rsa_verifying, marker='o', label='Verifying (ops/sec)')
plt.plot(rsa_keys, rsa_encrypting, marker='o', label='encrypting (ops/sec)')
plt.plot(rsa_keys, rsa_decrypting, marker='o', label='Decrypting (ops/sec)')
plt.xscale('log', base=2)
plt.yscale('log')
plt.xticks(rsa_keys, rsa_keys)
plt.xlabel('RSA Key Size (bits)')
plt.ylabel('Operations per Second (log scale)')
plt.title('RSA Performance')
plt.legend()
plt.grid(True, which='both', linestyle='--', linewidth=0.5)

# AES Performance Subplot
plt.subplot(1, 2, 2)
plt.plot(aes_block_sizes, aes_128_throughput, marker='o', label='AES-128-CBC (MB/s)')
plt.plot(aes_block_sizes, aes_192_throughput, marker='o', label='AES-192-CBC (MB/s)')
plt.plot(aes_block_sizes, aes_256_throughput, marker='o', label='AES-256-CBC (MB/s)')
plt.xscale('log')
plt.yscale('log')
plt.xticks(aes_block_sizes, aes_block_sizes, rotation=45)
plt.xlabel('AES Block Size (bytes)')
plt.ylabel('Throughput (MB/s, log scale)')
plt.title('AES Performance')
plt.legend()
plt.grid(True, which='both', linestyle='--', linewidth=0.5)

plt.tight_layout()
plt.show()

# PKCS#7 Padding
def pkcs7_pad(data, block_size=16): #16 bytes block size for AES that is 128 bits
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)
# unpadding
def pkcs7_unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# ECB Mode Implementation
def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    #print(blocks)
    return b''.join(cipher.encrypt(block) for block in blocks) #b'' is the delimeter used to join the blocks as bit object

# CBC Mode Implementation
def encrypt_cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    encrypted_data = b''
    prev_cipher_block = iv
    for block in blocks:
        block = bytes(a ^ b for a, b in zip(block, prev_cipher_block))
        cipher_block = cipher.encrypt(block)
        encrypted_data += cipher_block
        prev_cipher_block = cipher_block
    return encrypted_data

#CBC decryption
def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_data = b''
    prev_cipher_block = iv
    for block in blocks:
        decrypted_block = cipher.decrypt(block)
        decrypted_data += bytes(a ^ b for a, b in zip(decrypted_block, prev_cipher_block))
        prev_cipher_block = block
    return decrypted_data

def submit(user_input, key, iv):
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    user_input = user_input.replace("=", "").replace(";", "")
    full_data = (prefix + user_input + suffix).replace("=", "%3D").replace(";", "%3B").encode('utf-8')
    # print("this is the full data",full_data)
    padded_data = pkcs7_pad(full_data)
    # print("this is the paded data",padded_data)
    # print()
    # print ("this is the paddeddata at index 0",chr(padded_data[16]))
    # print()
    ciphertext = encrypt_cbc(padded_data, key, iv)
    # print("this is the cipher data",ciphertext)
    # print()
    # print ("this is the ciphertext at index 0",ciphertext[0])
    # print()
    return ciphertext

def verify(ciphertext, key, iv):
    plaintext = decrypt_cbc(ciphertext, key, iv)
    # unpad plaintext
    plaintext = pkcs7_unpad(plaintext)
    # convert url encoded plaintext to string
    plaintext = plaintext.decode("utf-8",errors="ignore").replace("%3D", "=").replace("%3B", ";")
    # check if ;admin=true; is in plaintext
    return ';admin=true;' in plaintext

def xor_byte(data, index, original_char, target_char):
    # XOR the byte at the given index with the original character and target character
    data[index] ^= ord(original_char) ^ ord(target_char)

def bit_modification(modifdata):
    # Convert ciphertext to mutable bytearray
     
     data = bytearray(modifdata)
     xor_byte(data, 16, '1', ';')
     xor_byte(data, 22, '1', '=')  
     xor_byte(data, 27, '1', ';')  
    #  print("this is bytes data: ", bytes(data))
     return bytes(data)

# Main Function
def main(filename, key, iv=None, mode='ECB'):
    with open(filename, 'rb') as f:
        bmp_data = f.read()
    
    header = bmp_data[:54]  # Adjust header size as needed
    pixel_data = bmp_data[54:]
    padded_data = pkcs7_pad(pixel_data)
    
    if mode == 'ECB':
        encrypted_data = encrypt_ecb(padded_data, key)
    elif mode == 'CBC':
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        encrypted_data = encrypt_cbc(padded_data, key, iv)
    
    with open(f"encrypted_{mode}.bmp", 'wb') as f:
        f.write(header + encrypted_data)
    
    user_input = "hello21admin1true1yo"

    encrypted_data = submit(user_input, key, iv) 
    bit_modificationData = bit_modification(encrypted_data)
    verification = verify(bit_modificationData, key, iv)
    print("this is the verification result",verification)
    return verification

# Example Usage
key = get_random_bytes(16)
iv = get_random_bytes(16)
main('mustang.bmp', key, iv, mode='CBC')
# main('cp-logo.bmp', key, mode='ECB')
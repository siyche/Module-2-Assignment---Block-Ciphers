from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# PKCS#7 Padding
def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

# ECB Mode Implementation
def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    return b''.join(cipher.encrypt(block) for block in blocks)

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

# Main Function
def encrypt_bmp(filename, key, iv=None, mode='ECB'):
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

# Example Usage
key = get_random_bytes(16)
iv = get_random_bytes(16)
encrypt_bmp('example.bmp', key, iv, mode='CBC')
encrypt_bmp('example.bmp', key, mode='ECB')

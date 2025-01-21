from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
    print("this is the full data",full_data)
    padded_data = pkcs7_pad(full_data)
    print("this is the paded data",padded_data)
    ciphertext = encrypt_cbc(padded_data, key, iv)
    print("this is the cipher data",ciphertext)
    print()
    print ("this is the ciphertext at index 0",ciphertext[0])
    print()
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
    """
    Modify a byte at a specific index by XORing it to transform
    `original_char` into `target_char`.
    """
    data[index] ^= ord(original_char) ^ ord(target_char)

def bit_modification(modifdata):
    # Convert ciphertext to mutable bytearray
     """
    Injects ";admin=true;" into the decrypted plaintext using XOR manipulation.
    """
     
     data = bytearray(modifdata)
     print(data)
     print(data[16])
     xor_byte(data, 16, '1', ';')  # Modify to inject `;`
     xor_byte(data, 22, '1', '=')  # Modify to inject `=`
     xor_byte(data, 27, '1', ';')  # Modify to inject `;`
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
    
    user_input = "1111111admin1true1"

    encrypted_data = submit(user_input, key, iv)

    is_admin = verify(encrypted_data, key, iv)
    print(f"Before modification - Is admin: {is_admin}")
    
    modified_data = bit_modification(encrypted_data)
    is_admin = verify(modified_data, key, iv)
    print(f"After modification - Is admin: {is_admin}")
    return is_admin

# Example Usage
key = get_random_bytes(16)
iv = get_random_bytes(16)
main('mustang.bmp', key, iv, mode='CBC')
# main('cp-logo.bmp', key, mode='ECB')
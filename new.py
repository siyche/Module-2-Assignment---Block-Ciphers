from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import subprocess
import re
import plotly.graph_objects as go


# --------TASK 1-------
def task1(key, iv):
    print("\n---------TASK 1---------\n")
    input_file = 'mustang.bmp'
    ecb_output_file = 'encrypted_ecb_' + input_file
    cbc_output_file = 'encrypted_cbc_' + input_file

    with open(input_file, 'rb') as file:
        bmp_header = file.read(54)
        bmp_image_data = file.read()

    ecb_image_data = ecb_encrypt(bmp_image_data, key)
    cbc_image_data = cbc_encrypt(bmp_image_data, key, iv)

    print("Image encrypted.")

    with open(ecb_output_file, 'wb') as file:
        file.write(bmp_header)
        file.write(ecb_image_data)

    with open(cbc_output_file, 'wb') as file:
        file.write(bmp_header)
        file.write(iv)
        file.write(cbc_image_data)

    print("Files written.")

# --------TASK 2-------
def task2(key, iv):
    print("\n---------TASK 2---------\n")
    user_input = "1111111admin1true1"
    encrypted_data = submit(user_input, key, iv)
    is_admin = verify(encrypted_data, key, iv)
    print(f"Before modification - Is admin: {is_admin}")
    
    modified_data = modify(encrypted_data)
    is_admin = verify(modified_data, key, iv)
    print(f"After modification - Is admin: {is_admin}")
    return is_admin
    
# --------TASK 2 Submit function-------    
def submit(user_input, key , iv):
    # sanitize user input for ; and = 
    user_input = user_input.replace("=", "")
    user_input = user_input.replace(";", "")
    
    data = "userid=456;userdata=" + user_input + ";session-id=31337"
    # url encode data's = and ;
    data = data.replace("=", "%3D")
    data = data.replace(";", "%3B")
    data = data.encode("utf-8")
    
    
    # pad string to be divisible by 16
    data = pad(data)
    # encrypt data
    data = cbc_encrypt(data, key, iv)
    return data
    
def verify(data, key, iv):
    # decrypt data (can use AES-CBC decrypt library)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)
    # unpad plaintext
    plaintext = unpad(plaintext)
    # convert url encoded plaintext to string
    plaintext = plaintext.decode("utf-8",errors="ignore")
    plaintext = plaintext.replace("%3D", "=")
    plaintext = plaintext.replace("%3B", ";")
    # check if ;admin=true; is in plaintext
    return ';admin=true;' in plaintext

def modify(data):

    data = bytearray(data)
    

    data[16] = data[16] ^ ord("1") ^ ord(';') 
    data[22] = data[22] ^ ord("1") ^ ord('=') 
    data[27] = data[27] ^ ord("1") ^ ord(';') 
    
        
    data = bytes(data)

    return data

# --------Padding-------
def pad(block):
    # ensure the block sizes are padded to be divisible by 128
    pad_len = AES.block_size - len(block) % AES.block_size
    return block + bytes([pad_len] * pad_len)


def unpad(padded_data):
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]

# -------Generate Random Key-------
def generate_key(size):
    return get_random_bytes(size)

# --------ECB Encryption-------
def ecb_encrypt(plaintext, key):
    # generate AES cipher and start of ciphertext
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""

    padded_text = pad(plaintext)

    # encrypt block by block
    for i in range(0, len(padded_text), AES.block_size):
        block = padded_text[i:i + AES.block_size]
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block

    return ciphertext

# --------CBC Encryption-------
def cbc_encrypt(plaintext, key, iv):
    ciphertext = b""
    prev_block = iv

    # loop through by blocksize, padding the block
    # create new cipher based on previous block 
    # apply and append to cyber text
    for i in range(0, len(plaintext), AES.block_size):
        block = plaintext[i:i + AES.block_size]
        block  = pad(block)

        cipher = AES.new(key, AES.MODE_ECB)

        xor_res = bytes(x ^ y for x, y in zip(block, prev_block))

        encrypted_block = cipher.encrypt(xor_res)

        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext

def run_openssl_speed(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True, shell=True)
    return result.stdout

def parse_rsa_output(output):
    data = []
    lines = output.split('\n')
    for line in lines[5:-1]:
        words = line.split()
        print(words)
        data.append((int(words[1]), float(words[5]), float(words[6])))
    return data

def parse_aes_output(output):
    data = []
    lines = output.split('\n')
    print(lines)
    for line in lines[6:9]:
        words = line.split()
        print(words)
        data.append((int(words[0][-3:]), float(words[2][:-1]), float(words[3][:-1]), float(words[4][:-1]), float(words[5][:-1]), float(words[6][:-1])))
    return data

def plot_rsa_graph(data):
     # Extract data for plotting
    key_sizes, public_throughput, private_throughput = zip(*data)

    # Create a colored bar chart
    fig = go.Figure()

    fig.add_trace(go.Bar(x=key_sizes, y=public_throughput, name='Public RSA', marker_color='blue'))
    fig.add_trace(go.Bar(x=key_sizes, y=private_throughput, name='Private RSA', marker_color='orange'))

    # Update layout
    fig.update_layout(barmode='group',
                    title='Key Size vs Public and Private Throughput',
                    xaxis=dict(title='Key Size'),
                    yaxis=dict(title='Throughput'))

    # Show the plot
    fig.show()

def plot_aes_graph(data):
     # Extract data for plotting
    block_size, k16, k64, k256, k1024, k8192 = zip(*data)

    # Create a colored bar chart
    fig = go.Figure()

    fig.add_trace(go.Bar(x=block_size, y=k16, name='16 Size Block', marker_color='blue'))
    fig.add_trace(go.Bar(x=block_size, y=k64, name='64 Size Block', marker_color='orange'))
    fig.add_trace(go.Bar(x=block_size, y=k256, name='256 Size Block', marker_color='red'))
    fig.add_trace(go.Bar(x=block_size, y=k1024, name='1024 Size Block', marker_color='pink'))
    fig.add_trace(go.Bar(x=block_size, y=k8192, name='8192 Size Block', marker_color='purple'))

    # Update layout
    fig.update_layout(barmode='group',
                    title='Key Size vs Throughput for various Block Size',
                    xaxis=dict(title='Key Size'),
                    yaxis=dict(title='Throughput'))

    # Show the plot
    fig.show()

def task3():
    rsa_command = 'openssl speed rsa'
    rsa_output = run_openssl_speed(rsa_command)
    rsa_data = parse_rsa_output(rsa_output)
    print(rsa_data)
    plot_rsa_graph(rsa_data)

    # Plot AES graph
    aes_command = 'openssl speed aes-128-cbc aes-192-cbc aes-256-cbc'
    aes_output = run_openssl_speed(aes_command)
    aes_data = parse_aes_output(aes_output)
    print(aes_data)
    plot_aes_graph(aes_data)
    

def main():
    # generate key and iv once
    key = generate_key(AES.block_size)
    iv = generate_key(AES.block_size)
    task1(key, iv)
    task2(key, iv)
    task3()


if __name__ == "__main__":
    main()
One-Time Pad Encryption Program

This repository contains a Python script that implements a one-time pad encryption system using XOR encryption. The script communicates with the random.org API to generate a truly random one-time pad, which is then used to encrypt and decrypt messages.
How the Code Works

The code is organized into several functions, each with a specific role in generating, saving, loading, encrypting, and decrypting a one-time pad.
1. get_api_key()

This function manages the API key needed to access the random.org API:

    Checks for the presence of an API key file (key.txt). If found, it reads the key from the file.
    If key.txt is missing, prompts the user to enter their API key and saves it to key.txt for future use.

python

def get_api_key():
    if os.path.exists("key.txt"):
        with open("key.txt", "r") as f:
            api_key = f.read().strip()
    else:
        api_key = input("Enter your random.org API key: ")
        with open("key.txt", "w") as f:
            f.write(api_key)
        print("API key saved to key.txt")
    return api_key

2. generate_one_time_pad(size, api_key)

This function interacts with the random.org API to create a one-time pad:

    Sends a request to generate size random integers between 0 and 255.
    Returns the list of integers, each representing a byte in the one-time pad.

python

def generate_one_time_pad(size, api_key):
    url = "https://api.random.org/json-rpc/4/invoke"
    payload = {
        "jsonrpc": "2.0",
        "method": "generateIntegers",
        "params": {
            "apiKey": api_key,
            "n": size,
            "min": 0,
            "max": 255,
            "replacement": True
        },
        "id": 1
    }
    response = requests.post(url, json=payload)
    data = response.json()
    if "error" in data:
        print("Error:", data["error"]["message"])
        return None
    random_numbers = data["result"]["random"]["data"]
    return random_numbers

3. save_pad_to_file(pad, filename="pad.txt")

This function saves the generated one-time pad to pad.txt in a comma-separated integer format.

python

def save_pad_to_file(pad, filename="pad.txt"):
    with open(filename, "w") as f:
        f.write(",".join(map(str, pad)))
    print(f"One-time pad saved to {filename} in integer format.")

4. load_pad_from_file(filename="pad.txt")

This function loads the one-time pad from pad.txt:

    Reads the comma-separated integers.
    Converts them back into a bytes object, making it ready for XOR encryption/decryption.

python

def load_pad_from_file(filename="pad.txt"):
    if not os.path.exists(filename):
        print(f"Error: {filename} does not exist.")
        return None
    with open(filename, "r") as f:
        pad_integers = list(map(int, f.read().split(',')))
    return bytes(pad_integers)

5. xor_bytes(data, pad)

Performs the XOR operation between each byte of the data and the corresponding byte of the pad, the core operation for both encryption and decryption.

python

def xor_bytes(data, pad):
    return bytes(a ^ b for a, b in zip(data, pad))

6. encrypt_message(pad)

This function reads a plaintext message from unencrypted.txt, encrypts it, and saves the result to message.txt in a readable integer format.

python

def encrypt_message(pad):
    if not os.path.exists("unencrypted.txt"):
        print("Error: unencrypted.txt does not exist.")
        return
    with open("unencrypted.txt", "rb") as f:
        message = f.read()
    if len(pad) < len(message):
        print("Error: One-time pad is too short for the message.")
        return
    encrypted_message = xor_bytes(message, pad[:len(message)])
    with open("message.txt", "w") as f:
        f.write(",".join(map(str, encrypted_message)))
    print("Message encrypted and saved to message.txt in integer format.")

7. decrypt_message(pad)

This function reads the encrypted message from message.txt, decrypts it, and writes the original plaintext to decrypted_message.txt.

python

def decrypt_message(pad):
    if not os.path.exists("message.txt"):
        print("Error: message.txt does not exist.")
        return
    with open("message.txt", "r") as f:
        encrypted_message_integers = list(map(int, f.read().split(',')))
    encrypted_message = bytes(encrypted_message_integers)
    if len(pad) < len(encrypted_message):
        print("Error: One-time pad is too short for the encrypted message.")
        return
    decrypted_message = xor_bytes(encrypted_message, pad[:len(encrypted_message)])
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_message)
    print("Message decrypted and saved to decrypted_message.txt")

8. main()

The main() function provides command-line options for generating a pad, encrypting, and decrypting messages.
How XOR Encryption and One-Time Pads Work
XOR Encryption

XOR (exclusive OR) is a binary operation used to combine data and the encryption key:

    Each bit of the output is 1 if the corresponding bits of the inputs differ, and 0 if they are the same.
    XOR has a unique property that allows the same operation to be used for both encryption and decryption. XORing twice with the same key returns the original data.

One-Time Pad Encryption

A one-time pad is an encryption method that uses XOR to produce theoretically unbreakable encryption when the following conditions are met:

    Random Key: The one-time pad must be truly random, as long as the message, and used only once.
    Encryption: Each byte of the plaintext is XORed with a corresponding byte from the one-time pad, producing a ciphertext that appears random.
    Perfect Secrecy: If the pad is random and used only once, it is impossible to determine the plaintext without the key.

Example

If the message is 1010 1100 and the one-time pad is 0110 1010, XOR encryption works as follows:

    Encryption:

    yaml

1010 1100 (message)
XOR 0110 1010 (one-time pad)
= 1100 0110 (ciphertext)

Decryption:

yaml

    1100 0110 (ciphertext)
    XOR 0110 1010 (one-time pad)
    = 1010 1100 (original message)

In Summary

The XOR operation and the randomness of the one-time pad provide simple and secure encryption. If each key is used only once and kept secret, the encryption is theoretically unbreakable.
Usage

    Generate a One-Time Pad:

    bash

./otp_program.py -p 16

Encrypt a Message:

bash

./otp_program.py -e

Decrypt a Message:

bash

    ./otp_program.py -d

Requirements

    Python 3.x
    requests library for API communication with random.org

Install requests using:

bash

pip install requests

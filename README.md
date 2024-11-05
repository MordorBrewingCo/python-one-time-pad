One-Time Pad Encryption Program

This repository contains a Python script that implements a one-time pad encryption system using XOR encryption. The script communicates with the random.org API to generate a truly random one-time pad, which is then used to encrypt and decrypt messages.
How the Code Works

The code is organized into several functions, each with a specific role in generating, saving, loading, encrypting, and decrypting a one-time pad.
1. get_api_key()

This function manages the API key needed to access the random.org API:

    Checks for the presence of an API key file (key.txt). If found, it reads the key from the file.
    If key.txt is missing, prompts the user to enter their API key and saves it to key.txt for future use.

2. generate_one_time_pad(size, api_key)

This function interacts with the random.org API to create a one-time pad:

    Sends a request to generate size random integers between 0 and 255.
    Returns the list of integers, each representing a byte in the one-time pad.

3. save_pad_to_file(pad, filename="pad.txt")

This function saves the generated one-time pad to pad.txt in a comma-separated integer format.
4. load_pad_from_file(filename="pad.txt")

This function loads the one-time pad from pad.txt:

    Reads the comma-separated integers.
    Converts them back into a bytes object, making it ready for XOR encryption and decryption.

5. xor_bytes(data, pad)

Performs the XOR operation between each byte of the data and the corresponding byte of the pad, which is the core operation for both encryption and decryption.
6. encrypt_message(pad)

This function reads a plaintext message from unencrypted.txt, encrypts it, and saves the result to message.txt in a readable integer format.

    Reads the plaintext message as bytes.
    Uses xor_bytes to encrypt the message with the one-time pad.
    Saves the encrypted result to message.txt in integer format.

7. decrypt_message(pad)

This function reads the encrypted message from message.txt, decrypts it, and writes the original plaintext to decrypted_message.txt.

    Reads the comma-separated integers from message.txt.
    Converts the integers to bytes and performs XOR decryption.
    Saves the decrypted result as binary in decrypted_message.txt.

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

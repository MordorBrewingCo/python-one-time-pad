#!/usr/bin/env python3

import argparse
import os

import requests


def get_api_key():
    # Check for existing key.txt file
    if os.path.exists("key.txt"):
        with open("key.txt", "r") as f:
            api_key = f.read().strip()
    else:
        # Prompt for API key if not found, then save it
        api_key = input("Enter your random.org API key: ")
        with open("key.txt", "w") as f:
            f.write(api_key)
        print("API key saved to key.txt")
    return api_key


def generate_one_time_pad(size, api_key):
    # URL for random.org's integer generation API
    # For free usage key, maximum of 10,000 integers per request.
    # Each integer can range from 0 to 255 if generating random bytes, so a single request could yield up to 10,000 bytes (10 KB).
    url = "https://api.random.org/json-rpc/4/invoke"

    # Prepare the API request payload
    payload = {
        "jsonrpc": "2.0",
        "method": "generateIntegers",
        "params": {
            "apiKey": api_key,
            "n": size,
            "min": 0,
            "max": 255,  # Byte range for a one-time pad
            "replacement": True
        },
        "id": 1
    }

    # Send the request to random.org API
    response = requests.post(url, json=payload)
    data = response.json()

    # Check for errors in the response
    if "error" in data:
        print("Error:", data["error"]["message"])
        return None

    # Retrieve the generated random numbers directly as integers (0 to 255)
    random_numbers = data["result"]["random"]["data"]
    return random_numbers  # Return as a list of integers


def save_pad_to_file(pad, filename="pad.txt"):
    # Save each byte in the pad as an integer, comma-separated
    with open(filename, "w") as f:
        f.write(",".join(map(str, pad)))
    print(f"One-time pad saved to {filename} in integer format.")


def load_pad_from_file(filename="pad.txt"):
    if not os.path.exists(filename):
        print(f"Error: {filename} does not exist.")
        return None
    with open(filename, "r") as f:
        # Read the comma-separated integers and convert to bytes
        pad_integers = list(map(int, f.read().split(',')))
    return bytes(pad_integers)


def xor_bytes(data, pad):
    return bytes(a ^ b for a, b in zip(data, pad))


def encrypt_message(pad):
    if not os.path.exists("unencrypted.txt"):
        print("Error: unencrypted.txt does not exist.")
        return

    with open("unencrypted.txt", "rb") as f:
        message = f.read()

    if len(pad) < len(message):
        print("Error: One-time pad is too short for the message.")
        return

    # Perform XOR encryption
    encrypted_message = xor_bytes(message, pad[:len(message)])

    # Save encrypted message as comma-separated integers
    with open("message.txt", "w") as f:
        f.write(",".join(map(str, encrypted_message)))
    print("Message encrypted and saved to message.txt in integer format.")


def decrypt_message(pad):
    if not os.path.exists("message.txt"):
        print("Error: message.txt does not exist.")
        return

    with open("message.txt", "r") as f:
        # Read the comma-separated integers and convert to bytes
        encrypted_message_integers = list(map(int, f.read().split(',')))
    encrypted_message = bytes(encrypted_message_integers)

    if len(pad) < len(encrypted_message):
        print("Error: One-time pad is too short for the encrypted message.")
        return

        # Perform XOR decryption
    decrypted_message = xor_bytes(encrypted_message, pad[:len(encrypted_message)])

    # Save the decrypted message as binary in decrypted_message.txt
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_message)
    print("Message decrypted and saved to decrypted_message.txt")


def main():
    parser = argparse.ArgumentParser(description="One-Time Pad Encryption Program")
    parser.add_argument("-p", "--pad", type=int, help="Generate a one-time pad of the specified size in bytes")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt unencrypted.txt using pad.txt")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt message.txt using pad.txt")
    args = parser.parse_args()

    if args.pad:
        api_key = get_api_key()
        pad = generate_one_time_pad(args.pad, api_key)
        if pad:
            save_pad_to_file(pad)

    elif args.encrypt:
        pad = load_pad_from_file()
        if pad:
            encrypt_message(pad)

    elif args.decrypt:
        pad = load_pad_from_file()
        if pad:
            decrypt_message(pad)

    else:
        print("Please specify an option: -p <size> to generate pad, -e to encrypt, or -d to decrypt.")


if __name__ == "__main__":
    main()

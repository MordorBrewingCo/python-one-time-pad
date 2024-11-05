# One-Time Pad Encryption Program

This Python script provides a command-line tool for performing encryption and decryption using a one-time pad. The script generates a truly random one-time pad via the random.org API, encrypts messages with XOR encryption, and provides secure decryption.

## Features

- **Generate One-Time Pads**: Uses random.org to generate a one-time pad of a specified length.
- **Encrypt Messages**: Encrypts a plaintext message from `unencrypted.txt` using XOR and the one-time pad, saving the result to `message.txt`.
- **Decrypt Messages**: Decrypts the contents of `message.txt` back to plaintext and saves it in `decrypted_message.txt`.
- **Uses XOR Operation**: XOR is used to encrypt and decrypt data in a straightforward, reversible way.

## Requirements

- Python 3
- `requests` library (`pip install requests`)
- A valid API key from [random.org](https://www.random.org)

## Files

- `key.txt`: Stores the API key for random.org.
- `pad.txt`: Stores the one-time pad in a human-readable, comma-separated integer format.
- `unencrypted.txt`: Contains the plaintext message to be encrypted.
- `message.txt`: Stores the encrypted message as a comma-separated list of integers.
- `decrypted_message.txt`: Contains the decrypted message, restored to its original binary format.

## Usage

### 1. Generate a One-Time Pad

To generate a one-time pad, use the `-p` option followed by the pad size (in bytes). This saves the pad to `pad.txt`.


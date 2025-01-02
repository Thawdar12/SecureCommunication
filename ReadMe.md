# Secure Communication Protocol Implementation

This project implements a secure communication protocol using cryptographic techniques, enabling encrypted and authenticated message exchange between two parties. It uses Java's cryptographic libraries to demonstrate concepts such as symmetric and asymmetric encryption, message authentication, and nonce-based freshness.

## Key Features

1. **Public Key Cryptography:**
   - Public/private key pairs for secure communication.
   - Use of modular arithmetic to compute shared secrets.

2. **Symmetric Encryption:**
   - AES-based encryption and decryption of messages using shared secret keys.

3. **Message Authentication:**
   - SHA-1 based Message Authentication Code (MAC) ensures data integrity.

4. **Nonce for Freshness:**
   - Random nonces prevent replay attacks and ensure message uniqueness.

5. **Key Exchange Principles:**
   - Implements the Diffie-Hellman mechanism to establish shared secret keys.

6. **Error Handling:**
   - Verifies MAC and detects tampered messages.
   - Handles invalid key inputs gracefully.

7. **Secure Communication Flow:**
   - Sender encrypts the message, computes MAC, and sends `(g^r, C, MAC)` to the receiver.
   - Receiver validates the MAC and decrypts the message.

## What I learnt

1. Basics of **public key cryptography** and **symmetric encryption**.
2. **Java Cryptography API** usage for encryption, decryption, and hashing.
3. Efficient **modular arithmetic** using `BigInteger`.
4. Generating cryptographic keys from integers using `SecretKeySpec`.
5. Handling byte arrays and encoding with **Base64**.
6. Error handling for invalid inputs and cryptographic validation.
7. Building a secure communication protocol with encryption and authentication.

## How It Works

1. **Sender Workflow:**
   - Computes \( g^r \) using a random nonce \( r \).
   - Derives a shared secret key \( TK \) from the receiver's public key.
   - Encrypts the message \( M \) using \( TK \).
   - Computes the linking key \( LK \) and the MAC.
   - Sends \( g^r, C, \text{MAC} \) to the receiver.

2. **Receiver Workflow:**
   - Computes \( TK \) and \( LK \) from the sender's \( g^r \) and public key.
   - Verifies the MAC for integrity.
   - Decrypts the encrypted message \( C \) to retrieve \( M \).

## Requirements

- Java Development Kit (JDK) 8 or later.
- Basic understanding of cryptography (public/private keys, AES, SHA-1).

## How to Run

1. Compile the code using:
   ```bash
   javac csci368A1.java

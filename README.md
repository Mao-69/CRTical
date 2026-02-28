# CRTical

## Overview

CRTical is a professional-grade cryptographic research utility that
demonstrates RSA private key recovery when a Chinese Remainder Theorem
(CRT) exponent (`dp = d mod (p-1)`) is exposed.

The tool automates factor recovery, full private key reconstruction
using OpenSSL 3.x native APIs, and RSA-OAEP (SHA-256) decryption.

This project is intended strictly for security research, auditing, and
defensive cryptography education.

------------------------------------------------------------------------

## Background

RSA implementations commonly use Chinese Remainder Theorem (CRT)
optimization to improve decryption performance. This introduces
auxiliary values:

-   `dp = d mod (p - 1)`
-   `dq = d mod (q - 1)`

If `dp` is leaked through logs, crash dumps, memory disclosure, or
improper debugging output, the RSA modulus can be factored efficiently.

Given:

    e * dp ≡ 1 (mod p - 1)

It follows that:

    e * dp - 1 = k * (p - 1)

Allowing recovery of `p` using GCD techniques against the public modulus
`n`.

Exposure of CRT parameters is equivalent to private key compromise.

------------------------------------------------------------------------

## Features

-   RSA prime factor recovery from leaked `dp`
-   Support for raw hexadecimal input
-   Support for base64url + zlib encoded fragments
-   JSONL crash log parsing
-   Private key reconstruction via OpenSSL 3.x EVP_PKEY_fromdata API
-   RSA-OAEP (SHA-256) decryption
-   Export of reconstructed private key (PEM format)
-   Configurable search window for correction factor

------------------------------------------------------------------------

## Requirements

-   OpenSSL 3.x
-   GMP
-   zlib
-   GCC or Clang

------------------------------------------------------------------------

## Build

    gcc -O2 -o CRTical CRTical.c -lssl -lcrypto -lz -lgmp

------------------------------------------------------------------------

## Usage

### Recover from raw dp (hex)

    ./CRTical       --pub public.pem       --dphex <hex_value>       --cipher encrypted.bin

### Recover from encoded fragments

    ./CRTical       --pub public.pem       --chunks <chunk1> <chunk2> ...       --cipher encrypted.bin

### Recover from crash log (JSONL)

    ./CRTical       --pub public.pem       --jsonl crash.jsonl       --cipher encrypted.bin

------------------------------------------------------------------------

## Command Line Options

  -----------------------------------------------------------------------
  Option                       Description
  ---------------------------- ------------------------------------------
  --pub                        RSA public key (PEM)

  --dphex                      Leaked dp value (hex)

  --chunks                     Base64url + zlib fragments

  --jsonl                      JSONL crash log containing fragments

  --cipher                     RSA-OAEP encrypted blob

  --out                        Output file (default: decrypted.bin)

  --save-pem                   Output private key file (default:
                               recovered_private.pem)

  --max-delta                  GCD correction search window (default:
                               1048576)

  --no-decrypt                 Recover key only
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Security Implications

Systems may be vulnerable if:

-   Crash logs include private key components
-   Debug logging exposes BIGNUM internals
-   Memory disclosure vulnerabilities leak CRT parameters
-   Improper sandboxing allows state inspection

Mitigation recommendations:

-   Never log private key material
-   Disable verbose logging in production crypto services
-   Use secure memory handling
-   Prefer hardware-backed key storage (HSM, TPM)
-   Monitor logs for sensitive data exposure

------------------------------------------------------------------------

## Example Output

    [+] Public key loaded (2048-bit modulus)
    [+] dp recovered
    [+] Searching for factor...
    [+] Factor found
    [+] Private key reconstructed
    [+] Decryption successful

------------------------------------------------------------------------

## Legal Notice

This software is provided for:

-   Security research
-   Cryptographic auditing
-   Authorized penetration testing
-   Defensive education

Unauthorized use against systems without explicit permission may violate
applicable laws.

Use responsibly.

# SHA-256 in C++ — Educational Project

This repository contains an implementation of **SHA-256 in C++** (soon to be done in Rust too!), created as part of a practical learning experience about low-level programming, bitwise operations, and byte manipulation.

---

## Project Objective

The goal of this project is not to compete with existing optimized libraries, but to **deeply understand** how SHA-256 works at the level of bits, bytes, and memory:

- Learn to work with fixed data types (`uint8_t`, `uint32_t`).
- Understand padding and the preparation of 512-bit blocks.
- Experiment with bit rotations, shifts, and bitwise operators.
- Apply masks and logical combinations (AND, OR, XOR, NOT) to build the compression functions.
- Follow the internal logic of SHA-256: the calculations of T1 and T2, block expansion, and updating the hash variables.

---

## Project Contents

- `sha256.hpp` — Declaration of the SHA256 class and its functions.
- `sha256.cpp` — Implementation of the functions:
  - Rotations (`ROTR`, `ROTL`) and shifts (`SHR`).
  - Sigma functions (`Σ0`, `Σ1`) and sigma (`σ0`, `σ1`).
  - Auxiliary functions `Ch` and `Maj`.
  - Padding management and processing of 512-bit blocks.
  - Final generation of the 256-bit digest.
- `main.cpp` — Test program to calculate the hash of arbitrary messages.

---

## Learnings and Conclusions

1. **Bitwise and byte manipulation**  
   Working with `uint32_t` and `uint8_t` allows you to control bits individually and explore how rotations, shifts, and masks build complex cryptographic functions.

2. **Padding and block preparation**  
   SHA-256 divides the message into 512-bit blocks, adds a `1` bit, pads with zeros, and finally includes the length of the message in bits. This ensures the hash is deterministic and unique for each input.

3. **Sigma functions and compression logic**  
   The T1 and T2 operations combine rotations and logical operators precisely. Although the mathematical logic behind SHA-256 was defined by cryptographers, implementing it step by step helps you understand how small changes in the bits affect the result.

4. **Use of pointers and reinterpret_cast**  
   To pass a message of type `char*` to `uint8_t*` and work byte by byte, `reinterpret_cast` is necessary. This is a practical example of how C++ allows you to reinterpret memory without copying data.

5. **Debugging and progressive understanding**  
   Through intermediate prints and byte analysis, you can see how the message is transformed at each phase, reinforcing the understanding of each SHA-256 operation.

---

## How to use it

1. Clone the repository:

```bash
git clone https://github.com/r6h/sha256.git
```

2. Compile:

```bash
g++ -std=c++17 main.cpp sha256.cpp -o sha256
```

3. Execute, you should see the hash of the message defined in **main.cpp**

## Final Reflection

This project is an example of how cryptographic theory translates into code. Although SHA-256 may seem abstract, implementing it from scratch reveals the importance of each operation at the bit level, and how C++ allows detailed control over memory and data types. Will do it again once I start learning Rust :)
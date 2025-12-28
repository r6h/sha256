#include "sha256.hpp"
#include <cstring>
#include <iostream>
#include <iomanip>

// Initial constants (H0..H7)
static const uint32_t H0[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

//  K-Constants (64 values SHA-256)
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// Constructor
SHA256::SHA256(bool debug_) : totalLenBits(0), debug(debug_) {
    message.reserve(64);
    std::memcpy(H, H0, sizeof(H0));
}

// bitwise operations
uint32_t SHA256::ROTR(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}
uint32_t SHA256::SHR(uint32_t x, unsigned n)  {
    return x >> n;
}

// sha256 logic
uint32_t SHA256::Sigma0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

uint32_t SHA256::Sigma1(uint32_t x) {
    return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25);
}

uint32_t SHA256::sigma0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3);
}
uint32_t SHA256::sigma1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x,19) ^ SHR(x, 10);
}

// choose and majority
uint32_t SHA256::Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t SHA256::Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// add data to message
void SHA256::update(const uint8_t* data, size_t len) {
    totalLenBits += len * 8;
    message.insert(message.end(), data, data + len);
    printMessage("After update");
}

// add standard padding
void SHA256::padMessage() {
    size_t len = message.size();
    message.push_back(0x80);
    while ((message.size() + 8) % 64 != 0) {
        message.push_back(0x00);
    }
    for (int i = 7; i >= 0; i--) {
        message.push_back((totalLenBits >> (8 * i)) & 0xFF);
    }
    printMessage("After padding");
}

void SHA256::printMessage(const std::string& label) {
    if (!debug) return;
    std::cout << label << ": ";
    for (uint8_t b : message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << std::endl;
}

// process a 512 bit block
void SHA256::processBlock(const uint8_t* block) {
    if (debug) {
        std::cout << "Processing block: ";
        for (int i = 0; i < 64; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)block[i];
        std::cout << std::dec << std::endl;
    }

    uint32_t W[64];

    // first 16 words
    for (int i = 0; i < 16; i++) {
        W[i] =
            (block[4*i + 0] << 24) |
            (block[4*i + 1] << 16) |
            (block[4*i + 2] <<  8) |
            (block[4*i + 3] <<  0);
    }

    // rest of the block
    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }

    // init job variables
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    // 64 rounds, circular shift
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + Sigma1(e) + ((e & f) ^ (~e &  g)) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + ((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // update hash
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

// execute padding, process block and return output
std::array<uint8_t, 32> SHA256::digest() {
    padMessage();

    for (size_t i = 0; i < message.size(); i += 64) {
        processBlock(&message[i]);
    }

        std::array<uint8_t, 32> out;

        for (int i = 0; i < 8; i++) {
            out[4*i + 0] = (H[i] >> 24) & 0xFF;
            out[4*i + 1] = (H[i] >> 16) & 0xFF;
            out[4*i + 2] = (H[i] >> 8 ) & 0xFF;
            out[4*i + 3] = (H[i] >> 0 ) & 0xFF;
        }
        
    return out;
}
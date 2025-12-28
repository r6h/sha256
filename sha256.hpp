#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

class SHA256 {
public:
    SHA256(bool debug = false);

    void update(const uint8_t* data, size_t len);
    std::array<uint8_t, 32> digest();

    static uint32_t ROTR(uint32_t x, unsigned n);
    static uint32_t SHR(uint32_t x, unsigned n);
    static uint32_t Sigma0(uint32_t x); // ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)
    static uint32_t Sigma1(uint32_t x); // ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)
    static uint32_t sigma0(uint32_t x); // ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3)
    static uint32_t sigma1(uint32_t x); // ROTR(x, 17) ^ ROTR(x,19) ^ SHR(x, 10)

private:
    void processBlock(const uint8_t* block);
    void padMessage();

    uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
    uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

    void printMessage(const std::string& label);

    std::vector<uint8_t> message;
    uint64_t totalLenBits;
    uint32_t H[8];
    bool debug;
};
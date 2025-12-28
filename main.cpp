#include <iostream>
#include <iomanip>
#include "sha256.hpp"

int main() {
    SHA256 sha(true); // Enable debugging

    const char* msg= "abc";
    sha.update(reinterpret_cast<const uint8_t*>(msg), 3);

    auto hash = sha.digest();
    
    for (uint8_t byte : hash) {
        std::cout << std::hex
                  << std::setw(2)
                  << std::setfill('0')
                  << (int)byte;
    }

    std::cout << std::endl;

    return 0;
}
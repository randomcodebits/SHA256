#include <iostream>
#include <array>
#include <cstdint>

#include "sha.h"

using namespace std;

template <typename T>
void hexdump(T b, T e) {
    for(;b != e; ++b) {
        uint8_t v = *b;
        printf("%02x", v);
    }
    printf("\n");
}

int main() {
    sha256_buf buf;
    buf.raw.fill(0);

    array<uint8_t, sha256::hash_size> result = {0};

    auto buf_ptr = reinterpret_cast<basic_istream<char>::char_type*>(buf.data_block.raw.data());
    sha256 hash;
    while(!cin.eof()){
        cin.read(buf_ptr, buf.data_block.raw.size());
        size_t read = cin.gcount();

        if(read == buf.data_block.raw.size()) {
            hash.add_data_block(buf);
        } else {
            hash.add_final_block(buf, read, result);
        }
    }

    hexdump(begin(result), end(result));
    cout << endl;
}
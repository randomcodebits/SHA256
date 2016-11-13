#include <array>
#include <cstdint>
#include <algorithm>
#include <endian.h>
#include <cassert>
#include <cstring>
#include <iostream>

#include <iomanip>

#include "sha.h"

using namespace std;

//sha table
array<uint32_t, 64> sha256_table_k = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u
};


sha256::sha256() {
    //sha hash init constants

    this->hash.words[0] = 0x6A09E667ul;
    this->hash.words[1] = 0xBB67AE85ul;
    this->hash.words[2] = 0x3C6EF372ul;
    this->hash.words[3] = 0xA54FF53Aul;
    this->hash.words[4] = 0x510E527Ful;
    this->hash.words[5] = 0x9B05688Cul;
    this->hash.words[6] = 0x1F83D9ABul;
    this->hash.words[7] = 0x5BE0CD19ul;
}

uint32_t rightrotate(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

bool sha256::can_expand(uint64_t size) {
    return (size % 512 + 1 + sizeof(uint64_t)) < block_size_bytes;
}

void sha256::expand_message(struct sha256_buf &buf, uint64_t message_size) {
    fill(begin(buf.raw) + message_size, end(buf.raw), 0);
    buf.raw[message_size] = 0x80;

    this->processed_size += message_size;

    uint64_t len_to_write = htobe64(this->processed_size * 8);
    if(this->can_expand(message_size))
        buf.data_block.length = len_to_write;
    else
        buf.expand_block.length = len_to_write;
}

void sha256::add_data_block(struct sha256_buf &buf) {
    this->add_block(buf.data_block);
}

void sha256::add_block(sha256_block &block) {
    array<uint32_t, 64> w;

    for(int i = 0; i<16; ++i){
        w[i] = htobe32(block.words[i]);
    }

    for(uint32_t i = 16; i < 64; ++i){
        uint32_t s0 = rightrotate( w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = this->hash.words[0];
    uint32_t b = this->hash.words[1];
    uint32_t c = this->hash.words[2];
    uint32_t d = this->hash.words[3];
    uint32_t e = this->hash.words[4];
    uint32_t f = this->hash.words[5];
    uint32_t g = this->hash.words[6];
    uint32_t h = this->hash.words[7];

    for(uint32_t i = 0; i < w.size(); ++i) {
        uint32_t S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_table_k[i] + w[i];
        uint32_t S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    this->hash.words[0] += a;
    this->hash.words[1] += b;
    this->hash.words[2] += c;
    this->hash.words[3] += d;
    this->hash.words[4] += e;
    this->hash.words[5] += f;
    this->hash.words[6] += g;
    this->hash.words[7] += h;

    this->processed_size += block_size_bytes;
}

void sha256::add_final_block(struct sha256_buf &buf, uint64_t block_size,  array<uint8_t, hash_size> &result) {
    this->expand_message(buf, block_size);
    this->add_block(buf.data_block);
    if(!this->can_expand(block_size))
        this->add_block(buf.expand_block);

    for(auto& i : this->hash.words){
        i = htobe32(i);
    }

    copy(begin(this->hash.raw), end(this->hash.raw), begin(result));
}


#include <array>
#include <cstdint>

using namespace std;

union sha256_block;
union sha256_hash;


class sha256 {
public:
    sha256();
    static const size_t block_size_bits = 512;
    static const size_t block_size_bytes = block_size_bits / 8;
    static const size_t block_size_words = block_size_bits / 32;
    static const size_t hash_size = 256 / 8;

    void add_data_block(struct sha256_buf &buf);
    void add_final_block(struct sha256_buf &buf, uint64_t block_size, array<uint8_t, hash_size> &result);

    inline uint64_t get_processed_size() const { return this->processed_size; }

private:
    union sha256_hash {
        array<uint8_t, hash_size> raw;
        array<uint32_t, hash_size / sizeof(uint32_t)> words;
    };

    union sha256_hash hash;
    uint64_t processed_size = 0;

    bool can_expand(uint64_t size);
    void expand_message(struct sha256_buf &buf, uint64_t message_size);
    void add_block(sha256_block &block);
};



union sha256_block {
    array<uint8_t, sha256::block_size_bytes> raw;
    array<uint32_t, sha256::block_size_words> words;

    struct {
        array<uint8_t, sha256::block_size_bytes - sizeof(uint64_t)> raw_no_length;
        uint64_t length;
    };
};

static_assert(
    sizeof(sha256_block) == sizeof(sha256_block::raw_no_length) + sizeof(sha256_block::length),
    "size must match"
);

static_assert(
    sizeof(sha256_block::raw) == sizeof(sha256_block::words),
    "sha256_block part size must match"
);

struct sha256_buf {
    union {
        struct{
            sha256_block data_block;
            sha256_block expand_block;
        };
        array<uint8_t, sha256::block_size_bytes * 2> raw;
    };
};


static_assert(
    sizeof(sha256_buf) == sizeof(sha256_buf::raw),
    "size must match"
);
static_assert(
    sizeof(sha256_buf) == sizeof(sha256_buf::data_block) + sizeof(sha256_buf::expand_block),
    "size must match"
);

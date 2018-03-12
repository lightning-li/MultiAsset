//计算 note commitment 时所用到的 gadget
template<typename FieldT>
class note_commitment_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    note_commitment_gadget(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a_pk,
        pb_variable_array<FieldT>& v,
        pb_variable_array<FieldT>& rho,
        pb_variable_array<FieldT>& r,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb) {
        // note commitment 生成时用到的前缀 10110000
        pb_variable_array<FieldT> leading_byte =
            from_bits({1, 0, 1, 1, 0, 0, 0, 0}, ZERO);

        pb_variable_array<FieldT> first_of_rho(rho.begin(), rho.begin()+184);
        pb_variable_array<FieldT> last_of_rho(rho.begin()+184, rho.end());

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

        // final padding
        // sha256 函数需要将输入解析成多个 512 bit 的 block，
        // 当输入长度不足 512 的整数倍时，需要进行填充，
        // 填充规则为：假设输入消息 M 的长度为 l (以 bits 来计算，"abc" 的长度为 24)，
        // 首先在消息 M 后追加位 1，然后 k 个位 0，k 是这样计算而出的：满足 l + 1 + k = 448 mod 512 等式的最小非负解，
        // 最后需要添加表示长度的位串使得消息整个长度为 512 的整数倍。
        // 例如，计算 note commitment 时输入的长度为 840 位，则 k = 448 + 512 - 840 - 1 = 119 个 0；
        // 现在整个消息的长度是 840 + 120 = 960 bit，因此还差 512*2 - 960 = 64 bit，因此使用 1101001000 来表示 840，
        // 并在前面补充 0
        pb_variable_array<FieldT> length_padding =
            from_bits({
                // padding
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,

                // length of message (840 bits)
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,1,
                0,1,0,0,1,0,0,0
            }, ZERO);

        // 8 + 256 + 64 + 184 bit (rho 的一部分) = 512 bit
        block1.reset(new block_variable<FieldT>(pb, {
            leading_byte,
            a_pk,
            v,
            first_of_rho
        }, ""));

        // 72 + 256 + 184 bit = 512 bit
        block2.reset(new block_variable<FieldT>(pb, {
            last_of_rho,
            r,
            length_padding
        }, ""));

        // 使用 sha256 时，需对每一个 block 进行处理，初始时有一个默认的初始哈希值，
        // sha256_compression_function_gadget 函数每次接收前一个 block 产生的哈希值，
        // 以及当前 block 的内容，生成的结果哈希放入第四个参数中。 
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        ""));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *result,
        ""));
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

template<typename FieldT>
class merkle_tree_gadget : gadget<FieldT> {
private:
    typedef sha256_two_to_one_hash_gadget<FieldT> sha256_gadget;

    // 存放 Merkle 分支中节点处于的位置，即左与右两种，当为 1 时，分支中节点处于左子树，为 0 则分支节点处于右子树
    // 即当 position 中的元素为 0 时，哈希值应该这样计算：hash(leaf, branch_node)
    pb_variable_array<FieldT> positions;
    // 存放求根哈希值过程中使用到的 INCREMENTAL_MERKLE_TREE_DEPTH 个左节点与右节点的根哈希值
    std::shared_ptr<merkle_authentication_path_variable<FieldT, sha256_gadget>> authvars;
    // 用来检测 merkle 分支是否有效
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, sha256_gadget>> auth;

public:
    merkle_tree_gadget(
        protoboard<FieldT>& pb,
        digest_variable<FieldT> leaf,
        digest_variable<FieldT> root,
        pb_variable<FieldT>& enforce
    ) : gadget<FieldT>(pb) {

        // allocate 函数会调用 INCREMENTAL_MERKLE_TREE_DEPTH 次 pb 中的 allocate_var_index 函数，在 pb 中的 r1cs 变量中增加一个 FieldT 元素，
        // 并且返回所分配变量在 pb 中的索引，假设是第一次调用 allocate_var_index 函数，那么返回的索引值为 1，
        // 索引值 0 保留为 r1cs 变量中的常量
        positions.allocate(pb, INCREMENTAL_MERKLE_TREE_DEPTH);
        
        // 生成 merkle_authentication_path_variable 时，也会在 pb 的 r1cs 变量中分配相应数量（2 * INCREMENTAL_MERKLE_TREE_DEPTH * 256）的元素
        authvars.reset(new merkle_authentication_path_variable<FieldT, sha256_gadget>(
            pb, INCREMENTAL_MERKLE_TREE_DEPTH, "auth"
        ));

        /*
        flag is true : when packing src/target root to field, copy src root (computed root according to leaf/path)
        to target root, so when generating witness, root_digest must be called after merkle_tree_check_read_gadget.
        otherwise root_digest will be overwrite by ml, In this case, given a wrong root, it will pass.
        flag is false : don't do above. so when generating witness, root_digest must be called before merkle_tree_check_read_gadget.
        otherwise, when calling ml generate_r1cs_witness, it will be packing empty/wrong target root, causing packed_source and
        packed_target not equal, it will not pass. 因为在调用 ml->generate_r1cs_witness() 函数的时候，会将 target 对应的位数组打包成
        多个 FieldT 元素，而在调用 ml->generate_r1cs_constraints() 的时候，会将 target 位数组与打包成的多个 FieldT 元素进行等式约束绑定，
        所以如果不在调用 ml->generate_r1cs_witness() 之前先调用 root_digest->generate_r1cs_witness()，那么在调用 ml->generate_r1cs_witness()
        的时候，target 其实是全 0 位数组，将其打包成为多个 FieldT::zero() 的元素，而后再次调用 root_digest->generate_r1cs_witness() 后，
        target 在 pb 中对应的值就会变成 root，那么当再次检查等式约束是否成立时，就会出现 target 位数组与打包好的多个 FieldT 元素不匹配的错误
        */
        
        auth.reset(new merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            INCREMENTAL_MERKLE_TREE_DEPTH,
            positions,
            leaf,
            root,
            *authvars,
            enforce,
            ""
        ));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < INCREMENTAL_MERKLE_TREE_DEPTH; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }

        authvars->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const MerklePath& path) {
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convertVectorToInt(path.index);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        authvars->generate_r1cs_witness(path_index, path.authentication_path);
        auth->generate_r1cs_witness();
    }
};

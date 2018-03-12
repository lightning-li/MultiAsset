/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#ifndef DIGEST_SELECTOR_GADGET_TCC_
#define DIGEST_SELECTOR_GADGET_TCC_

namespace libsnark {

template<typename FieldT>
digest_selector_gadget<FieldT>::digest_selector_gadget(protoboard<FieldT> &pb,
                                                       const size_t digest_size,
                                                       const digest_variable<FieldT> &input,
                                                       const pb_linear_combination<FieldT> &is_right,
                                                       const digest_variable<FieldT> &left,
                                                       const digest_variable<FieldT> &right,
                                                       const std::string &annotation_prefix) :
gadget<FieldT>(pb, annotation_prefix), digest_size(digest_size), input(input), is_right(is_right), left(left), right(right)
{
}

template<typename FieldT>
void digest_selector_gadget<FieldT>::generate_r1cs_constraints()
{
    // 当 is_right 为 1 时，input = right
    // 当 is_right 为 0 时，input  = left
    for (size_t i = 0; i < digest_size; ++i)
    {
        /*
          input = is_right * right + (1-is_right) * left
          input - left = is_right(right - left)
        */
        // 假设 is_right 所代表的变量在 pb 中的位置为 is_right_index
        // right.bits[i] 所代表的变量在 pb 中的位置为 right_i_index
        // left.bits[i] 所代表的变量在 pb 中的位置为 left_i_index
        // input.bits[i] 所代表的变量在 pb 中的位置为 input_i_index
        // r1cs_constraint 的参数均为 liner_combination 类型
        // 添加的等式约束为：{FieldT::one()(系数) * pb[is_right_index - 1]} * {FieldT::one() *  (pb[right_i_index] - pb[left_i_index])} = {FieldT::one() * (pb[input_i_index] - pb[left_i_index])}
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]),
                                     FMT(this->annotation_prefix, " propagate_%zu", i));
    }
}

template<typename FieldT>
void digest_selector_gadget<FieldT>::generate_r1cs_witness()
{
    is_right.evaluate(this->pb);

    assert(this->pb.lc_val(is_right) == FieldT::one() || this->pb.lc_val(is_right) == FieldT::zero());
    if (this->pb.lc_val(is_right) == FieldT::one())
    {
        for (size_t i = 0; i < digest_size; ++i)
        {
            this->pb.val(right.bits[i]) = this->pb.val(input.bits[i]);
        }
    }
    else
    {
        for (size_t i = 0; i < digest_size; ++i)
        {
            this->pb.val(left.bits[i]) = this->pb.val(input.bits[i]);
        }
    }
}

} // libsnark

#endif // DIGEST_SELECTOR_GADGET_TCC_

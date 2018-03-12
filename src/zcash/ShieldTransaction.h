
#ifndef BUBI_SHIELDTRANSACTION_H
#define BUBI_SHIELDTRANSACTION_H

//#include <boost/array.h>
#include <array>
#include <functional>

#include "utils/uint256.h"
#include "zcash/Zcash.h"
#include "zcash/NoteEncryption.hpp"
#include "zcash/Proof.hpp"
#include "zcash/JoinSplit.hpp"
#include "zcash/random.h"

class JSDescription {
public:
    // vpub_old 代表进入到该匿名交易的金额
    // vpub_new 代表从该匿名交易出去的金额
    int64_t vpub_old;
    int64_t vpub_new;

    // 每一个 JSDescription 都关联着一个由历史上出现过的所有 note commitment 组成的 Merkle 树根哈希值 
    uint256 anchor;

    std::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;
    std::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    uint256 ephemeralKey;

    std::array<ZCNoteDecryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{ {{0}} }};

    uint256 randomSeed;

    std::array<uint256, ZC_NUM_JS_INPUTS> macs;

    libzcash::ZCProof proof;

    JSDescription(): vpub_old(0), vpub_new(0) {

    }

    JSDescription(ZCJoinSplit& params,
                const uint256& pubKeyHash,
                const uint256& rt,
                const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
                const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
                int64_t vpub_old,
                int64_t vpub_new,
                bool computeProof = true,
                uint256 *esk = nullptr    
                );
    
    static JSDescription Randomized(ZCJoinSplit& params,
                const uint256& pubKeyHash,
                const uint256& rt,
                std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
                std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
                std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
                std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
                int64_t vpub_old,
                int64_t vpub_new,
                bool computeProof = true,
                uint256 *esk = nullptr,
                std::function<int(int)> gen = GetRandInt
                );
    
    // 验证 JoinSplit 的证据是否是正确的
    bool Verify(
        ZCJoinSplit& params,
        libzcash::ProofVerifier& verifier,
        const uint256& pubKeyHash
    ) const;

    // 返回计算出的 h_sig
    uint256 h_sig(ZCJoinSplit& params, const uint256& pubKeyHash) const;

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vpub_old);
        READWRITE(vpub_new);
        READWRITE(anchor);
        READWRITE(nullifiers);
        READWRITE(commitments);
        READWRITE(ephemeralKey);
        READWRITE(randomSeed);
        READWRITE(macs);
        READWRITE(proof);
        READWRITE(ciphertexts);
    } 

    friend bool operator==(const JSDescription& a, const JSDescription& b) {
        return (
            a.vpub_old == b.vpub_old &&
            a.vpub_new == b.vpub_new &&
            a.anchor == b.anchor &&
            a.nullifiers == b.nullifiers &&
            a.commitments == b.commitments &&
            a.ephemeralKey == b.ephemeralKey &&
            a.ciphertexts == b.ciphertexts &&
            a.randomSeed == b.randomSeed &&
            a.macs == b.macs &&
            a.proof == b.proof
        );
    }

    friend bool operator!=(const JSDescription& a, const JSDescription& b) {
        return !(a == b);
    }
};

#endif
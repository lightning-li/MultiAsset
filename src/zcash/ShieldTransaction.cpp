
#include "zcash/ShieldTransaction.h"

JSDescription::JSDescription(ZCJoinSplit& params,
                const uint256& pubKeyHash,
                const uint256& rt,
                const std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
                const std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
                int64_t vpub_old,
                int64_t vpub_new,
                bool computeProof,
                uint256 *esk    
                ) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor)
{
    std::array<libzcash::Note, ZC_NUM_JS_OUTPUTS> notes;

    proof = params.prove(
        inputs,
        outputs,
        notes,
        ciphertexts,
        ephemeralKey,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        anchor,
        computeProof,
        esk
    );
}

JSDescription JSDescription::Randomized(
                ZCJoinSplit& params,
                const uint256& pubKeyHash,
                const uint256& anchor,
                std::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
                std::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
                std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
                std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
                int64_t vpub_old,
                int64_t vpub_new,
                bool computeProof,
                uint256 *esk,
                std::function<int(int)> gen
)
{
    inputMap = {0, 1};
    outputMap = {0, 1};
     assert(gen);

     MappedShuffle(inputs.begin(), inputMap.begin(), ZC_NUM_JS_INPUTS, gen);
     MappedShuffle(outputs.begin(), outputMap.begin(), ZC_NUM_JS_OUTPUTS, gen);

     return JSDescription(params, pubKeyHash, anchor, inputs, outputs, vpub_old, vpub_new, computeProof, esk);
}

bool JSDescription::Verify(ZCJoinSplit& params,
                           libzcash::ProofVerifier& verifier,
                           const uint256& pubKeyHash) const
{
    return params.verify(proof, verifier, pubKeyHash, randomSeed, macs, nullifiers, commitments, vpub_old, vpub_new, anchor);
}

uint256 JSDescription::h_sig(ZCJoinSplit& params, const uint256& pubKeyHash) const {
    return params.h_sig(randomSeed, nullifiers, pubKeyHash);
}
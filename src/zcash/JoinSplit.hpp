#ifndef ZC_JOINSPLIT_H_
#define ZC_JOINSPLIT_H_

#include "zcash/Zcash.h"
#include "zcash/Proof.hpp"
#include "zcash/Address.hpp"
#include "zcash/Note.hpp"
#include "zcash/IncrementalMerkleTree.hpp"
#include "zcash/NoteEncryption.hpp"

#include "utils/uint256.h"
#include "utils/uint252.h"

//#include <boost/array.hpp>
#include<array>

namespace libzcash {

class JSInput {
public:
    ZCIncrementalWitness witness;
    Note note;
    SpendingKey key;

    JSInput(uint256 id);
    JSInput(ZCIncrementalWitness witness,
            Note note,
            SpendingKey key) : witness(witness), note(note), key(key) { }

    uint256 nullifier() const {
        return note.nullifier(key);
    }
};

class JSOutput {
public:
    PaymentAddress addr;
    uint64_t value;
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};  // 0xF6 is invalid UTF8 as per spec, rest of array is 0x00
    uint256 id;

    JSOutput(uint256 id);
    JSOutput(PaymentAddress addr, uint64_t value, uint256 id) : addr(addr), value(value), id(id) { }

    Note note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig, uint256& id) const;
};

template<size_t NumInputs, size_t NumOutputs>
class JoinSplit {
public:
    virtual ~JoinSplit() {}

    static void Generate(const std::string r1csPath,
                         const std::string vkPath,
                         const std::string pkPath);

    static void GenerateNoteGadget(const std::string r1csPath,
                         const std::string vkPath,
                         const std::string pkPath);

    static JoinSplit<NumInputs, NumOutputs>* Prepared(const std::string vkPath,
                                                      const std::string pkPath);

    static uint256 h_sig(const uint256& randomSeed,
                         const std::array<uint256, NumInputs>& nullifiers,
                         const uint256& pubKeyHash
                        );

    virtual ZCProof prove(
        const std::array<JSInput, NumInputs>& inputs,
        const std::array<JSOutput, NumOutputs>& outputs,
        std::array<Note, NumOutputs>& out_notes,
        std::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
        uint256& out_ephemeralKey,
        const uint256& pubKeyHash,
        uint256& out_randomSeed,
        std::array<uint256, NumInputs>& out_hmacs,
        std::array<uint256, NumInputs>& out_nullifiers,
        std::array<uint256, NumOutputs>& out_commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt,
        const uint256& id,
        bool computeProof = true,
        // For paymentdisclosure, we need to retrieve the esk.
        // Reference as non-const parameter with default value leads to compile error.
        // So use pointer for simplicity.
        uint256 *out_esk = nullptr
    ) = 0;

    virtual bool verify(
        const ZCProof& proof,
        ProofVerifier& verifier,
        const uint256& pubKeyHash,
        const uint256& randomSeed,
        const std::array<uint256, NumInputs>& hmacs,
        const std::array<uint256, NumInputs>& nullifiers,
        const std::array<uint256, NumOutputs>& commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt,
        const uint256& id
    ) = 0;

protected:
    JoinSplit() {}
};

}

typedef libzcash::JoinSplit<ZC_NUM_JS_INPUTS,
                            ZC_NUM_JS_OUTPUTS> ZCJoinSplit;

#endif // ZC_JOINSPLIT_H_

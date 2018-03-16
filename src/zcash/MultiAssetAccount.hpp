#include <map>
#include "utils/uint256.h"
#include "utils/uint252.h"
#include "zcash/Note.hpp"
#include "utils/serialize.h"
#include "Zcash/IncrementalMerkleTree.hpp"

using namespace libzcash;

class MultiAssetAccount {

public:
    std::map<uint256, uint64_t> asset;
    uint252 a_sk;
    // true 代表 未花费，false 代表已花费
    std::vector<std::pair<Note, bool>> notes;
    std::map<uint256, ZCIncrementalWitness> note_witnesses;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(asset);
        READWRITE(a_sk);
        READWRITE(notes);
        READWRITE(note_witnesses);
    }
};
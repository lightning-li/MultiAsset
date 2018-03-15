#include <map>
#include "utils/uint256.h"
#include "utils/uint252.h"
#include "zcash/Note.hpp"
#include "utils/serialize.h"

using namespace libzcash;

class MultiAssetAccount {

public:
    std::map<uint256, uint64_t> asset;
    uint252 a_sk;
    std::vector<Note> notes;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(asset);
        READWRITE(a_sk);
        READWRITE(notes);
    }
};
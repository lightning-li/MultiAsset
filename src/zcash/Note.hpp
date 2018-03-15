#ifndef ZC_NOTE_H_
#define ZC_NOTE_H_

#include "utils/uint256.h"
#include "zcash/Zcash.h"
#include "zcash/Address.hpp"
#include "zcash/NoteEncryption.hpp"

#include <array>

namespace libzcash {

class Note {
public:
    uint256 a_pk;
    uint64_t value;
    uint256 rho;
    uint256 r;
    uint256 id;     // asset id

    Note(uint256 a_pk, uint64_t value, uint256 rho, uint256 r, uint256 id)
        : a_pk(a_pk), value(value), rho(rho), r(r), id(id) {}

    Note();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        
        READWRITE(a_pk);
        READWRITE(value);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(id);
    }

    uint256 cm() const;
    uint256 nullifier(const SpendingKey& a_sk) const;
};

class NotePlaintext {
public:
    uint64_t value = 0;
    uint256 rho;
    uint256 r;
    // add asset id
    uint256 id;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;

    NotePlaintext() {}

    NotePlaintext(const Note& note, std::array<unsigned char, ZC_MEMO_SIZE> memo);

    Note note(const PaymentAddress& addr) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = 0x00;
        READWRITE(leadingByte);

        if (leadingByte != 0x00) {
            throw std::ios_base::failure("lead byte of NotePlaintext is not recognized");
        }

        READWRITE(value);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(id);
        READWRITE(memo);
    }

    static NotePlaintext decrypt(const ZCNoteDecryption& decryptor,
                                 const ZCNoteDecryption::Ciphertext& ciphertext,
                                 const uint256& ephemeralKey,
                                 const uint256& h_sig,
                                 unsigned char nonce
                                );

    ZCNoteEncryption::Ciphertext encrypt(ZCNoteEncryption& encryptor,
                                         const uint256& pk_enc
                                        ) const;
};

}

#endif // ZC_NOTE_H_

#include "zcash/Address.hpp"
#include "zcash/NoteEncryption.hpp"
#include "utils/hash.h"
#include "zcash/prf.h"
#include "utils/streams.h"
#include "utils/version.h"

namespace libzcash {

uint256 PaymentAddress::GetHash() const {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    return Hash(ss.begin(), ss.end());
}

uint256 ViewingKey::pk_enc() {
    return ZCNoteEncryption::generate_pubkey(*this);
}

ViewingKey SpendingKey::viewing_key() const {
    return ViewingKey(ZCNoteEncryption::generate_privkey(*this));
}

SpendingKey SpendingKey::random() {
    return SpendingKey(random_uint252());
}

PaymentAddress SpendingKey::address() const {
    return PaymentAddress(PRF_addr_a_pk(*this), viewing_key().pk_enc());
}

}

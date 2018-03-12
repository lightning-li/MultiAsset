// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include "../util.h"
//#include "primitives/transaction.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/ShieldTransaction.h"
#include <libsnark/common/profiling.hpp>
#include "crypto/common.h"
#include <array>
#include <iostream>
#include <sys/time.h>

using namespace libzcash;
using namespace std;

bool generate_vk_pk(string pkFile, string vkFile, string r1csFile)
{
    if (init_and_check_sodium() == -1) {
        return false;
    }

    ZCJoinSplit::Generate(r1csFile, vkFile, pkFile);
    return true;
}

bool test_joinsplit(ZCJoinSplit* js) {
    // Create verification context.
    auto verifier = libzcash::ProofVerifier::Strict();

    // The recipient's information.
    SpendingKey recipient_key = SpendingKey::random();
    PaymentAddress recipient_addr = recipient_key.address();

    // Create the commitment tree
    ZCIncrementalMerkleTree tree;

    // Set up a JoinSplit description
    uint256 ephemeralKey;
    uint256 randomSeed;
    uint64_t vpub_old = 10;
    uint64_t vpub_new = 0;
    uint256 pubKeyHash = random_uint256();
    std::array<uint256, 2> macs;
    std::array<uint256, 2> nullifiers;
    std::array<uint256, 2> commitments;
    uint256 rt = tree.root();
    std::array<ZCNoteEncryption::Ciphertext, 2> ciphertexts;
    ZCProof proof;
    struct timeval start, end;
    {
        std::array<JSInput, 2> inputs = {
            JSInput(), // dummy input
            JSInput() // dummy input
        };

        std::array<JSOutput, 2> outputs = {
            JSOutput(recipient_addr, 10),
            JSOutput() // dummy output
        };

        std::array<Note, 2> output_notes;
        gettimeofday(&start, NULL);
        // Perform the proof
        proof = js->prove(
            inputs,
            outputs,
            output_notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        );
        gettimeofday(&end, NULL);
        std::cout << "---------------generate proof needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;

    }

    // Verify the transaction:
    if (js->verify(
        proof,
        verifier,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        rt
    )) {
        std::cout << "verify passed....." << std::endl;
    } else {
        return false;
    }

    // Recipient should decrypt
    // Now the recipient should spend the money again
    auto h_sig = js->h_sig(randomSeed, nullifiers, pubKeyHash);
    ZCNoteDecryption decryptor(recipient_key.viewing_key());

    auto note_pt = NotePlaintext::decrypt(
        decryptor,
        ciphertexts[0],
        ephemeralKey,
        h_sig,
        0
    );

    auto decrypted_note = note_pt.note(recipient_addr);

    if (decrypted_note.value != 10) {
        cout << "error...." << endl;
        return false;
    }

    // Insert the commitments from the last tx into the tree
    tree.append(commitments[0]);
    auto witness_recipient = tree.witness();
    tree.append(commitments[1]);
    witness_recipient.append(commitments[1]);
    vpub_old = 0;
    vpub_new = 1;
    rt = tree.root();
    pubKeyHash = random_uint256();

    {
        std::array<JSInput, 2> inputs = {
            JSInput(), // dummy input
            JSInput(witness_recipient, decrypted_note, recipient_key)
        };

        SpendingKey second_recipient = SpendingKey::random();
        PaymentAddress second_addr = second_recipient.address();

        std::array<JSOutput, 2> outputs = {
            JSOutput(second_addr, 9),
            JSOutput() // dummy output
        };

        std::array<Note, 2> output_notes;
        gettimeofday(&start, NULL);
        // Perform the proof
        proof = js->prove(
            inputs,
            outputs,
            output_notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        );
        gettimeofday(&end, NULL);
        std::cout << "generate zero knowledge needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;
    }

    // Verify the transaction:
    if (js->verify(
        proof,
        verifier,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        rt
    )) {
        cout << "Congratulations!! SUCCESS" << endl;
    } else {
        return false;
    }
    gettimeofday(&start, NULL);
    std::cout << "verify zero knowledge needs " << (1000000 * (start.tv_sec - end.tv_sec) + (start.tv_usec - end.tv_usec)) << " microseconds" << std::endl;

}

int main(int argc, char **argv)
{
    libsnark::start_profiling();

    char* home = getenv("HOME");
    string param_path;
    
    if (home == NULL || strlen(home) == 0) {
        param_path = "/.zcash-params";
    } else {
        param_path = string(home) + "/.zcash-params";
    }

    struct timeval start, end;
    gettimeofday(&start, NULL);
    auto p = ZCJoinSplit::Prepared(string(param_path + "/sprout-verifying.key"),
                                  (string(param_path + "/sprout-proving.key")));
    gettimeofday(&end, NULL);
    std::cout << "prepared vk and pk needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;
    // construct a proof.
    /*
    for (int i = 0; i < 5; i++) {
        uint256 anchor = ZCIncrementalMerkleTree().root();
        uint256 pubKeyHash;

        JSDescription jsdesc(*p,
                             pubKeyHash,
                             anchor,
                             {JSInput(), JSInput()},
                             {JSOutput(), JSOutput()},
                             0,
                             0);
    }
    */
    test_joinsplit(p);
    delete p; // not that it matters
}

// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include "../util.h"
//#include "primitives/transaction.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/ShieldTransaction.h"
#include <libsnark/common/profiling.hpp>
#include "crypto/common.h"
#include "zcash/MultiAssetAccount.hpp"
#include "utils/streams.h"
#include "utils/version.h"

#include <array>
#include <iostream>
#include <sys/time.h>
#include <stdio.h>
#include <cassert>

#include "rocksdb/db.h" 

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

// 随机生成 100 个地址，并赋予每个地址 100 个 MS1coin 和 100 个 MS2coin

void initial_multi_asset() {
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, "/home/likang/git/MultiAsset/walletDB", &db);
    assert(status.ok());
    uint252 a_sk;
    uint256 id1 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    uint256 id2 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");
    uint256 a_pk;

    for (int i = 0; i < 100; ++i) {
        a_sk = random_uint252();
        a_pk = SpendingKey(a_sk).address().a_pk;
        string a_pk_hex = a_pk.GetHex();
        std::cout << "a_sk is " << a_sk.inner().GetHex() << " and the a_pk is " << a_pk_hex << std::endl;

        MultiAssetAccount account;
        account.a_sk = a_sk;
        account.asset[id1] = 100;
        account.asset[id2] = 100;

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

        ss << account;
        std::string serialize_data = ss.str();

        std::cout << "write a_pk_hex " << a_pk_hex << "  and MultiAssetAccount " << serialize_data << " in to rocksdb." << std::endl;
        rocksdb::Status s = db->Put(rocksdb::WriteOptions(), a_pk_hex, serialize_data);
    }
    delete db;
}

void load_account_from_db() {
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status = rocksdb::DB::Open(options, "/home/likang/git/MultiAsset/walletDB", &db);
    assert(status.ok());
    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::cout << it->key().ToString() << ": " << it->value().ToString() << std::endl;
        MultiAssetAccount maa;
        string value = it->value().ToString();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << value;
        ss >> maa;
        
        std::cout << "private key is " << maa.a_sk.inner().GetHex() << std::endl;

        for (auto iter = maa.asset.begin(); iter != maa.asset.end(); ++iter) {
            std::cout << "asset id " << (iter->first).GetHex() << " value " << iter->second << std::endl; 
        }

    }
    assert(it->status().ok());
    delete it;
    delete db;
}

bool test_multi_asset_joinsplit(ZCJoinSplit* js) {
    
    // 创建验证上下文环境
    auto verifier = libzcash::ProofVerifier::Strict();
    
    // 伪造接收者信息
    SpendingKey recipient_key = SpendingKey::random();
    PaymentAddress recipient_addr = recipient_key.address();

    // 创建匿名资产承诺树
    ZCIncrementalMerkleTree tree;

    // 创建 JoinSplit 描述
    uint256 ephemeralKey;  // 创建临时公钥
    uint256 randomSeed;
    uint64_t vpub_old = 10;
    uint64_t vpub_new = 0;
    uint256 id = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    uint256 pubKeyHash = random_uint256();
    std::array<uint256, 2> macs;
    std::array<uint256, 2> nullifiers;
    std::array<uint256, 2> commitments;
    uint256 rt = tree.root();
    std::array<ZCNoteEncryption::Ciphertext, 2> ciphertexts;
    ZCProof proof;
    uint256 fake_id = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");
    struct timeval start, end;
    {
        std::array<JSInput, 2> inputs = {
            JSInput(id), // dummy input
            JSInput(id) // dummy input
        };

        std::array<JSOutput, 2> outputs = {
            JSOutput(recipient_addr, 10, fake_id),
            JSOutput(id) // dummy output
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
            rt,
            id
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
        rt,
        id
    )) {
        std::cout << "verify passed......" << std::endl;
    } else {
        std::cout << "verify failed......" << std::endl;
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
    /*
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
    */
}
/*
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
*/

void test_zero_proof() {
    libsnark::start_profiling();

    char* home = getenv("HOME");
    string param_path;
    
    if (home == NULL || strlen(home) == 0) {
        param_path = "/.zcash-params";
    } else {
        param_path = string(home) + "/.zcash-params";
    }

    struct timeval start, end;

    FILE* f;
    string vk_path = string(param_path + "/MultiAsset-verifying.key");
    string pk_path = string(param_path + "/MultiAsset-proving.key");
    string r1cs_path = string(param_path + "/MultiAsset-r1cs");

    f = fopen(vk_path.c_str(), "r");
    if (f == NULL) {
        cout << "verifying.key file not exits......" << endl;
        cout << "now generating vk pk and r1cs......" << endl;
        gettimeofday(&start, NULL);
        generate_vk_pk(pk_path, vk_path, r1cs_path);
        gettimeofday(&end, NULL);
        std::cout << "generate vk and pk needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;

    }

    gettimeofday(&start, NULL);
    auto p = ZCJoinSplit::Prepared(vk_path,
                                  pk_path);
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
    //test_multi_asset_joinsplit(p);
    delete p; // not that it matters
}

int main(int argc, char **argv)
{
    initial_multi_asset();
    load_account_from_db();
}

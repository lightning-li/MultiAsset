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
#include <map>
#include <sys/stat.h>

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

    for (int i = 0; i < 4; ++i) {
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

void load_account_from_db(std::map<uint256, MultiAssetAccount>& maas, ZCIncrementalMerkleTree& tree) {
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status = rocksdb::DB::Open(options, "/home/likang/git/MultiAsset/walletDB", &db);
    assert(status.ok());

    // load tree from rocksdb
    // 使用 "0x0000000000000000000000000000000000000000000000000000000000000000" 作为 tree 的 key
    string tree_key = "0x0000000000000000000000000000000000000000000000000000000000000000";
    string tree_value;
    rocksdb::Status st = db->Get(rocksdb::ReadOptions(), tree_key, &tree_value);
    if (st.ok()) {
        // unserialise tree_value to tree
        std::vector<char> vv(tree_value.c_str(), tree_value.c_str() + tree_value.size());
        CDataStream ss(vv, SER_NETWORK, PROTOCOL_VERSION);
        ss >> tree;
        std::cout << "tree's root loaded from rocksdb is " << tree.root().GetHex() << std::endl;
    } else {
        std::cout << "can not find tree in rocksdb" << std::endl;
    }
    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        // std::cout << it->key().ToString() << ": " << it->value().ToString() << std::endl;
        if (it->key().ToString() != tree_key) {
            MultiAssetAccount maa;
            string value = it->value().ToString();
            size_t value_len = value.size();
            std::vector<char> vv(value.c_str(), value.c_str() + value_len);
            CDataStream ss(vv, SER_NETWORK, PROTOCOL_VERSION);
            ss >> maa;
            maas[uint256S(it->key().ToString())] = maa;
            //std::cout << "private key is " << maa.a_sk.inner().GetHex() << std::endl;
            std::cout << it->key().ToString() << std::endl;
            for (auto iter = maa.asset.begin(); iter != maa.asset.end(); ++iter) {
                std::cout << "transparent asset id " << (iter->first).GetHex() << " value " << iter->second << std::endl; 
            }

            for (auto iter = maa.notes.begin(); iter != maa.notes.end(); ++iter) {
                std::cout << "note asset id " << iter->first.id.GetHex() << " value " << iter->first.value << std::endl;
                std::cout << "note commitment is " <<  iter->first.cm().GetHex() << "  note witness root is " << maa.note_witnesses[iter->first.cm()].root().GetHex() << std::endl; 
            }
        }
    }
    assert(it->status().ok());
    delete it;
    delete db;
}

// 测试多匿名资产生成
// 设钱包中的账户公有 n 个，n 为 4 的整数倍，该函数执行如下操作：
// 1. 1 => n/2+1、n/2+2; 2 => n/2+1、n/2+2 发送 value 为 random(1, 100) MS1coin。以此类推
// 2. n/2+1 => 1、2；n/2+2 => 1、2 发送 value 为 random(1, 100) MS2coin. 以此类推

bool test_multi_asset_joinsplit(ZCJoinSplit* js, std::map<uint256, MultiAssetAccount>& maas, ZCIncrementalMerkleTree& tree) {
    
    // 创建验证上下文环境
    auto verifier = libzcash::ProofVerifier::Strict();

    int maas_len = maas.size();
    auto maas_begin = maas.begin();
    uint256 id1 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    uint256 id2 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");
    
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status = rocksdb::DB::Open(options, "/home/likang/git/MultiAsset/walletDB", &db);
    assert(status.ok());

    for (int i = 0; i < maas_len / 2; ++i) {
        
        MultiAssetAccount sender_account = std::next(maas_begin, i)->second;

        SpendingKey recipient_key1 = SpendingKey(std::next(maas_begin, maas_len / 2 + i / 2)->second.a_sk);
        PaymentAddress recipient_addr1 = recipient_key1.address();
        SpendingKey recipient_key2 = SpendingKey(std::next(maas_begin, maas_len / 2 + i / 2 + 1)->second.a_sk);
        PaymentAddress recipient_addr2 = recipient_key2.address();

        // 创建临时公钥，用于与接收方协商出加密传输的对称密钥
        uint256 ephemeralKey;
        // 创建随机种子, 用于生成 JoinSplit 的签名
        uint256 randomSeed;
        // 创建 JoinSplitPubKey，用于生成 JoinSplit 的签名
        uint256 pubKeyHash = random_uint256();

        uint64_t v1 = GetRand(sender_account.asset[id1]);
        uint64_t v2 = GetRand(sender_account.asset[id1] - v1);
        uint64_t vpub_old = v1 + v2;
        assert(sender_account.asset[id1] >= vpub_old);
        std::next(maas_begin, i)->second.asset[id1] -= vpub_old;

        uint64_t vpub_new = 0;
        std::array<uint256, 2> macs;
        std::array<uint256, 2> nullifiers;
        std::array<uint256, 2> commitments;
        uint256 rt = tree.root();
        std::array<ZCNoteEncryption::Ciphertext, 2> ciphertexts;
        ZCProof proof;
        struct timeval start, end;
        
        std::array<JSInput, 2> inputs = {
            JSInput(id1), // dummy input
            JSInput(id1) // dummy input
        };

        std::array<JSOutput, 2> outputs = {
            JSOutput(recipient_addr1, v1, id1),
            JSOutput(recipient_addr2, v2, id1) 
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
            id1
        );
        gettimeofday(&end, NULL);
        std::cout << "---------------generate proof needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;
        
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
            id1
        )) {
            std::cout << "verify passed......" << std::endl;
        } else {
            gettimeofday(&start, NULL);
            std::cout << "verify failed......" << std::endl;
            std::cout << "---------------verify proof needs " << (1000000 * (start.tv_sec - end.tv_sec) + (start.tv_usec - end.tv_usec)) << " microseconds" << std::endl;
            return false;
        }
        
        // update account witness
        
        for (auto iter = maas.begin(); iter != maas.end(); ++iter) {
            auto maa = iter->second;
            for (auto it = maa.notes.begin(); it != maa.notes.end(); ++it) {
                if (it->second) {
                    iter->second.note_witnesses[it->first.cm()].append(commitments[0]);
                    iter->second.note_witnesses[it->first.cm()].append(commitments[1]);
                }
            }
        }
        
        tree.append(commitments[0]);
        maas[recipient_addr1.a_pk].notes.push_back(std::make_pair(output_notes[0], true));
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()] = tree.witness();
        tree.append(commitments[1]);  
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()].append(commitments[1]);
        maas[recipient_addr2.a_pk].notes.push_back(std::make_pair(output_notes[1], true));
        maas[recipient_addr2.a_pk].note_witnesses[output_notes[1].cm()] = tree.witness();

        // Recipient should decrypt
        // Now the recipient should spend the money again
        for (int i = 0; i < 2; ++i) {
            auto h_sig = js->h_sig(randomSeed, nullifiers, pubKeyHash);
            ZCNoteDecryption decryptor(i == 0 ? recipient_key1.viewing_key() : recipient_key2.viewing_key());

            auto note_pt = NotePlaintext::decrypt(
                decryptor,
                i == 0 ? ciphertexts[0] : ciphertexts[1],
                ephemeralKey,
                h_sig,
                i
            );

            auto decrypted_note = note_pt.note(i == 0 ? recipient_addr1 : recipient_addr2);

            if (decrypted_note.value != (i == 0 ? v1 : v2) || decrypted_note.id != id1) {
                std::cout << "error...." << std::endl;
                return false;
            } else {
                std::cout << "decrypt successfully......" << std::endl;
            }
        }
        
    }



    for (int i = maas_len / 2; i < maas_len; ++i) {
        
        MultiAssetAccount sender_account = std::next(maas_begin, i)->second;

        SpendingKey recipient_key1 = SpendingKey(std::next(maas_begin, (i-maas_len/2) / 2)->second.a_sk);
        PaymentAddress recipient_addr1 = recipient_key1.address();
        SpendingKey recipient_key2 = SpendingKey(std::next(maas_begin, (i-maas_len/2) / 2 + 1)->second.a_sk);
        PaymentAddress recipient_addr2 = recipient_key2.address();

        // 创建临时公钥，用于与接收方协商出加密传输的对称密钥
        uint256 ephemeralKey;
        // 创建随机种子, 用于生成 JoinSplit 的签名
        uint256 randomSeed;
        // 创建 JoinSplitPubKey，用于生成 JoinSplit 的签名
        uint256 pubKeyHash = random_uint256();

        uint64_t v1 = GetRand(sender_account.asset[id2]);
        uint64_t v2 = GetRand(sender_account.asset[id2] - v1);
        uint64_t vpub_old = v1 + v2;
        assert(sender_account.asset[id2] >= vpub_old);
        std::next(maas_begin, i)->second.asset[id2] -= vpub_old;
        uint64_t vpub_new = 0;
        std::array<uint256, 2> macs;
        std::array<uint256, 2> nullifiers;
        std::array<uint256, 2> commitments;
        uint256 rt = tree.root();
        std::array<ZCNoteEncryption::Ciphertext, 2> ciphertexts;
        ZCProof proof;
        struct timeval start, end;
        
        std::array<JSInput, 2> inputs = {
            JSInput(id2), // dummy input
            JSInput(id2) // dummy input
        };

        std::array<JSOutput, 2> outputs = {
            JSOutput(recipient_addr1, v1, id2),
            JSOutput(recipient_addr2, v2, id2) 
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
            id2
        );
        gettimeofday(&end, NULL);
        std::cout << "---------------generate proof needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;
        
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
            id2
        )) {
            std::cout << "verify passed......" << std::endl;
        } else {
            gettimeofday(&start, NULL);
            std::cout << "verify failed......" << std::endl;
            std::cout << "---------------verify proof needs " << (1000000 * (start.tv_sec - end.tv_sec) + (start.tv_usec - end.tv_usec)) << " microseconds" << std::endl;
            return false;
        }
        
        // update account witness
        for (auto iter = maas.begin(); iter != maas.end(); ++iter) {
            auto maa = iter->second;
            for (auto it = maa.notes.begin(); it != maa.notes.end(); ++it) {
                if (it->second) {
                    iter->second.note_witnesses[it->first.cm()].append(commitments[0]);
                    iter->second.note_witnesses[it->first.cm()].append(commitments[1]);
                }
            }
        }

        tree.append(commitments[0]);
        maas[recipient_addr1.a_pk].notes.push_back(std::make_pair(output_notes[0], true));
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()] = tree.witness();
        tree.append(commitments[1]);
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()].append(commitments[1]);
        maas[recipient_addr2.a_pk].notes.push_back(std::make_pair(output_notes[1], true));
        maas[recipient_addr2.a_pk].note_witnesses[output_notes[1].cm()] = tree.witness();
        // Recipient should decrypt
        // Now the recipient should spend the money again
        for (int i = 0; i < 2; ++i) {
            auto h_sig = js->h_sig(randomSeed, nullifiers, pubKeyHash);
            ZCNoteDecryption decryptor(i == 0 ? recipient_key1.viewing_key() : recipient_key2.viewing_key());

            auto note_pt = NotePlaintext::decrypt(
                decryptor,
                i == 0 ? ciphertexts[0] : ciphertexts[1],
                ephemeralKey,
                h_sig,
                i
            );

            auto decrypted_note = note_pt.note(i == 0 ? recipient_addr1 : recipient_addr2);

            if (decrypted_note.value != (i == 0 ? v1 : v2) || decrypted_note.id != id2) {
                std::cout << "error...." << std::endl;
                return false;
            } else {
                std::cout << "decrypt successfully......" << std::endl;
            }
        }
    }
    
    // write tree to rocksdb
    rocksdb::WriteBatch batch;
    string tree_key = "0x0000000000000000000000000000000000000000000000000000000000000000";
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tree;
    batch.Put(tree_key, ss.str());

    // write account into rocksdb
    for (auto iter = maas.begin(); iter != maas.end(); ++iter) {
        CDataStream cd(SER_NETWORK, PROTOCOL_VERSION);
        cd << iter->second;
        batch.Put(iter->first.GetHex(), cd.str());
    }
    status = db->Write(rocksdb::WriteOptions(), &batch);
    assert(status.ok());
    delete db;
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

// 测试多类型匿名资产转移
// 1. account[1] => account[n/2+1]、account[n/2+2] 发送匿名 MS2coin
// 2. account[n/2+1] => account[1]、account[2] 发送匿名 MS1coin

bool test_multi_asset_transfer(ZCJoinSplit* js, std::map<uint256, MultiAssetAccount>& maas, ZCIncrementalMerkleTree& tree) {
    auto verifier = libzcash::ProofVerifier::Strict();
    int maas_len = maas.size();
    auto maas_begin = maas.begin();
    uint256 id1 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    uint256 id2 = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");
    
    rocksdb::DB* db;
    rocksdb::Options options;
    rocksdb::Status status = rocksdb::DB::Open(options, "/home/likang/git/MultiAsset/walletDB", &db);
    assert(status.ok());

    for (int i = 0; i < maas_len / 2; ++i) {
        SpendingKey recipient_key1 = SpendingKey(std::next(maas_begin, maas_len / 2 + i / 2)->second.a_sk);
        PaymentAddress recipient_addr1 = recipient_key1.address();
        SpendingKey recipient_key2 = SpendingKey(std::next(maas_begin, maas_len / 2 + i / 2 + 1)->second.a_sk);
        PaymentAddress recipient_addr2 = recipient_key2.address();

        // 创建临时公钥，用于与接收方协商出加密传输的对称密钥
        uint256 ephemeralKey;
        // 创建随机种子, 用于生成 JoinSplit 的签名
        uint256 randomSeed;
        // 创建 JoinSplitPubKey，用于生成 JoinSplit 的签名
        uint256 pubKeyHash = random_uint256();

        // 设置为 0，只花费匿名资产并且只产生匿名资产
        uint64_t vpub_old = 0;
        uint64_t vpub_new = 0;

        MultiAssetAccount sender_account = std::next(maas_begin, i)->second;
        Note asset_old1 = sender_account.notes[0].first;
        assert(sender_account.notes[0].second);
        Note asset_old2 = sender_account.notes[1].first;
        assert(sender_account.notes[1].second);

        std::array<uint256, 2> macs;
        std::array<uint256, 2> nullifiers;
        std::array<uint256, 2> commitments;
        uint256 rt = tree.root();
        std::array<ZCNoteEncryption::Ciphertext, 2> ciphertexts;
        ZCProof proof;
        struct timeval start, end;

        JSInput js_input1(sender_account.note_witnesses[asset_old1.cm()], asset_old1, SpendingKey(sender_account.a_sk));
        JSInput js_input2(sender_account.note_witnesses[asset_old2.cm()], asset_old2, SpendingKey(sender_account.a_sk));

        std::array<JSInput, 2> inputs = {
            js_input1,
            js_input2
        };

        std::array<JSOutput, 2> outputs = {
            JSOutput(recipient_addr1, asset_old2.value, id2),
            JSOutput(recipient_addr2, asset_old1.value, id2)
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
            id2
        );
        gettimeofday(&end, NULL);
        std::cout << "---------------generate proof needs " << (1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)) << " microseconds" << std::endl;
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
            id2
        )) {
            std::cout << "verify passed......" << std::endl;
        } else {
            gettimeofday(&start, NULL);
            std::cout << "verify failed......" << std::endl;
            std::cout << "---------------verify proof needs " << (1000000 * (start.tv_sec - end.tv_sec) + (start.tv_usec - end.tv_usec)) << " microseconds" << std::endl;
            return false;
        }
        // 更新账户信息
        for (auto iter = maas.begin(); iter != maas.end(); ++iter) {
            auto maa = iter->second;
            for (auto it = maa.notes.begin(); it != maa.notes.end(); ++it) {
                if (it->second) {
                    iter->second.note_witnesses[it->first.cm()].append(commitments[0]);
                    iter->second.note_witnesses[it->first.cm()].append(commitments[1]);
                }
            }
        }

        tree.append(commitments[0]);
        maas[recipient_addr1.a_pk].notes.push_back(std::make_pair(output_notes[0], true));
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()] = tree.witness();
        tree.append(commitments[1]);
        maas[recipient_addr1.a_pk].note_witnesses[output_notes[0].cm()].append(commitments[1]);
        maas[recipient_addr2.a_pk].notes.push_back(std::make_pair(output_notes[1], true));
        maas[recipient_addr2.a_pk].note_witnesses[output_notes[1].cm()] = tree.witness();

        // Now the recipient should spend the money again
        for (int i = 0; i < 2; ++i) {
            auto h_sig = js->h_sig(randomSeed, nullifiers, pubKeyHash);
            ZCNoteDecryption decryptor(i == 0 ? recipient_key1.viewing_key() : recipient_key2.viewing_key());

            auto note_pt = NotePlaintext::decrypt(
                decryptor,
                i == 0 ? ciphertexts[0] : ciphertexts[1],
                ephemeralKey,
                h_sig,
                i
            );

            auto decrypted_note = note_pt.note(i == 0 ? recipient_addr1 : recipient_addr2);

            if (decrypted_note.value != (i == 0 ? asset_old2.value : asset_old1.value) || decrypted_note.id != id2) {
                std::cout << "error...." << std::endl;
                return false;
            } else {
                std::cout << "decrypt successfully......" << std::endl;
            }
        }
    }
     // write tree to rocksdb
    rocksdb::WriteBatch batch;
    string tree_key = "0x0000000000000000000000000000000000000000000000000000000000000000";
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tree;
    batch.Put(tree_key, ss.str());

    // write account into rocksdb
    for (auto iter = maas.begin(); iter != maas.end(); ++iter) {
        CDataStream cd(SER_NETWORK, PROTOCOL_VERSION);
        cd << iter->second;
        batch.Put(iter->first.GetHex(), cd.str());
    }
    status = db->Write(rocksdb::WriteOptions(), &batch);
    assert(status.ok());
    delete db;

}

void test_zero_proof(ZCJoinSplit* &js) {
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
    js = ZCJoinSplit::Prepared(vk_path,
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
    //delete js; // not that it matters
}

int main(int argc, char **argv)
{   
    struct stat st;
    if (stat("/home/likang/git/MultiAsset/walletDB", &st) == 0 && S_ISDIR(st.st_mode)) {
        std::cout << "walletDB is already exits, do not initialise it..." << std::endl;
    }
    else {
        std::cout << "walletDB is not here, do initialise it with 100 accounts" << std::endl;
        initial_multi_asset();
    }
    std::map<uint256, MultiAssetAccount> maas;
    ZCIncrementalMerkleTree tree;
    std::cout << "-----------load account from rocksdb--------------" << std::endl;
    load_account_from_db(maas, tree);
    ZCJoinSplit* js;
    test_zero_proof(js);
    //std::cout << "-----------test multi asset joinsplit--------------" << std::endl;
    //test_multi_asset_joinsplit(js, maas, tree);
    std::cout << "#############test multi asset transfer################" << std::endl;
    test_multi_asset_transfer(js, maas, tree);
    std::cout << "-----------load account from rocksdb again---------" << std::endl;
    std::map<uint256, MultiAssetAccount> maas1;
    ZCIncrementalMerkleTree tree1;
    load_account_from_db(maas, tree);
    
}

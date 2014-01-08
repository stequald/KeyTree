////////////////////////////////////////////////////////////////////////////////
//
// keytree.h
//
// Copyright (c) 2013-2014 Tim Lee
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef KEYTREE_KEYTREE_H
#define KEYTREE_KEYTREE_H

#include <iostream>
#include <vector>
#include "CoinClasses/hdkeys.h"
#include "logger.h"
#include "stringutils.h"


typedef struct {
    std::string chain;
    std::string extpub;
    std::string extprv;
    std::string privkey;
    std::string pubkey;
    std::string address;
} KeyNode;

class KeyTree {
public:
    KeyTree(const std::string seed, const std::string chainStr, StringUtils::StringFormat seedStringFormat);
    KeyTree(const std::string extKey, const std::string chainStr);
    KeyNode getNextInChain();
    KeyNode getCurrentInChain();
    bool isAtEndOfChain();
    static void setTestNet(bool enabled);
    static KeyNode getChildOfExtKey(const std::string extKey, uint32_t i);
    ~KeyTree() {}
private:
    bool isPrivate();
    static uchar_vector fromBase58ExtKey(const std::string extKey);
    uchar_vector fromBase58(const std::string str);
    static std::vector<uint32_t> parseChainString(const std::string chainStr, bool isPrivate = true);
    static inline uint32_t toPrime(uint32_t i) { return 0x80000000 | i; }
    static inline bool isPrime(uint32_t i) { return 0x80000000 & i; }
    static std::string iToString(uint32_t i);
    
    static std::string getAddressFromKeyChain(const Coin::HDKeychain& keyChain, uint32_t i);
    static std::pair<std::string,std::string> generatePrivateKey(const Coin::HDKeychain& keyChain, uint32_t i);
    
    static std::pair<uchar_vector,uchar_vector> CKD(uchar_vector k, uchar_vector c, uint32_t i);
    static std::pair<uchar_vector,uchar_vector> CKD_prime(uchar_vector K, uchar_vector c, uint32_t i);
    static std::pair<uchar_vector,uchar_vector> vectorTranverseCKD(std::vector<uint32_t> sequence, uchar_vector k, uchar_vector chain);
    static std::pair<uchar_vector,uchar_vector> vectorTranverseCKD_Prime(std::vector<uint32_t> sequence, uchar_vector k, uchar_vector chain);
    
    static std::string secretToASecret(const uchar_vector secret, bool compressed = false);
    static std::string public_key_to_bc_address(const uchar_vector public_key);
    static uchar_vector hash_160(const uchar_vector public_key);
    static std::string hash_160_to_bc_address(const uchar_vector h160, int addrtype = 0);
    static std::string encodeBase58Check(uchar_vector vchIn);
    
    uint32_t chain_idx;
    std::string chainname;
    Coin::HDKeychain prv;
    Coin::HDKeychain pub;
    Coin::HDKeychain parentpub;
    std::vector<uint32_t> chain;
};

#endif /* KEYTREE_KEYTREE_H */

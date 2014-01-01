////////////////////////////////////////////////////////////////////////////////
//
// keytree.cpp
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

#include "keytree.h"
#include <sstream>
#include <regex>
#include <cassert>
#include "hdkeys.h"
#include "Base58Check.h"

KeyTree::KeyTree(const std::string seed, const std::string chainStr) {
    uchar_vector s(seed);
    Coin::HDSeed hdSeed(s);
    bytes_t k = hdSeed.getMasterKey();
    bytes_t c = hdSeed.getMasterChainCode();
    
    Coin::HDKeychain prv(k, c);
    
    this->prv = prv;
    Coin::HDKeychain pub = prv.getPublic();
    this->pub = pub;
    this->chain = KeyTree::parseChainString(chainStr);
    this->chainname = "m";
    this->chain_idx = 0;
}

KeyTree::KeyTree(const std::string extKey, const std::string chainStr, uint32_t i_min, uint32_t i_max) {
    uchar_vector extendedKey;
    if (isBase58CheckValid(extKey))
        extendedKey = fromBase58ExtKey(extKey);
    else if (extKey.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
        extendedKey = uchar_vector(extKey);
    else
        throw std::runtime_error("Invalid extended key. Extended key must be in base58 or hex form.");
    
    Coin::HDKeychain key(extendedKey);
    
    this->prv = key; //may actually be public key
    Coin::HDKeychain pub = key.getPublic();
    this->pub = pub;
    
    if (key.isPrivate()) {
        this->chain = KeyTree::parseChainString(chainStr);
    }
    else {
        this->chain = KeyTree::parseChainString(chainStr, false);
    }
    
    this->chainname = "m";
    this->chain_idx = 0;
}

KeyNode KeyTree::getCurrentInChain() {
    KeyNode data;
    
    if(this->prv.isPrivate()) {
        data.extprv = toBase58Check(this->prv.extkey());
        //uchar_vector extkey(this->prv.extkey()); data.extprv = extkey.getHex();
    }

    data.extpub = toBase58Check(this->pub.extkey());
    //uchar_vector extkey(this->pub.extkey()); data.extpub = extkey.getHex();
    
    
    data.chain = this->chainname;
    
    if(this->prv.isPrivate()) {
        uchar_vector k = this->prv.key();
        k = k.getHex().substr(2);
        data.privkey = KeyTree::SecretToASecret(k, true);
    }

    uchar_vector K = this->prv.pubkey();
    data.address = KeyTree::public_key_to_bc_address(K);
    return data;
}

KeyNode KeyTree::getNextInChain() {
    if (this->isAtEndOfChain()) throw std::runtime_error("KeyTree is at end of chain.");
    
    // Append subtree label to name
    this->chainname += "/" + KeyTree::iToString(this->chain[this->chain_idx]);

    if (!KeyTree::isPrime(this->chain[this->chain_idx])) this->parentpub = this->pub;
    
    // Get child private and public keychains
    this->prv = this->prv.getChild(this->chain[this->chain_idx]);
    assert(this->prv);
    
    this->pub = this->prv.getPublic();
    assert(this->pub);
    
    // We need to make sure child of pub = pub of child for public derivation
    if (!KeyTree::isPrime(this->chain[this->chain_idx]))
        assert(this->pub == this->parentpub.getChild(this->chain[this->chain_idx]));
    
    this->chain_idx++;
    
    return this->getCurrentInChain();
}

KeyNode KeyTree::getChildOfExtKey(const std::string extKey, uint32_t i) {
    uchar_vector extendedKey;
    if (isBase58CheckValid(extKey))
        extendedKey = fromBase58ExtKey(extKey);
    else if (extKey.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
        extendedKey = uchar_vector(extKey);
    else
        throw std::runtime_error("Invalid extended key. Extended key must be in base58 or hex form.");

    Coin::HDKeychain key(extendedKey);
    
    Coin::HDKeychain privChild;
    Coin::HDKeychain pubChild;
    
    KeyNode data;

    if (key.isPrivate()) {
        privChild = key.getChild(i);
        pubChild = privChild.getPublic();
        data.extprv = toBase58Check(privChild.extkey());
        data.extpub = toBase58Check(pubChild.extkey());
    
        uchar_vector k = privChild.key();
        k = k.getHex().substr(2);
        data.privkey = KeyTree::SecretToASecret(k, true);
    } else {
        pubChild = key.getChild(i);
    }
    
    data.extpub = toBase58Check(pubChild.extkey());
    uchar_vector K = pubChild.pubkey();
    data.address = KeyTree::public_key_to_bc_address(K);
    return data;
}

bool KeyTree::isAtEndOfChain() {
    return this->chain_idx >= chain.size();
}

bool KeyTree::isPrivate() {
    return this->prv.isPrivate();
}

uchar_vector KeyTree::fromBase58ExtKey(const std::string extKey) {
    static unsigned int dummy = 0;
    uchar_vector fillKey;
    fromBase58Check(extKey, fillKey, dummy);
    static const std::string VERSION_BYTE("04");
    return uchar_vector(VERSION_BYTE+fillKey.getHex()); //append VERSION_BYTE to begining
}

std::vector<uint32_t> KeyTree::parseChainString(const std::string chainStr, bool isPrivate) {
    std::vector<uint32_t> chain;
    
    const std::string s = KeyTree::split(chainStr)[0]; //trim trailing whitespaces
    
    std::vector<std::string> splitChain = KeyTree::split(s, '/');

    //assert(splitChain[0] == "m" || splitChain[0] == "M");
    assert(splitChain[0] == "m");
    
    if (splitChain.back() == "") splitChain.pop_back(); // happens if chainStr has '/' at end
    
    for(auto it=splitChain.begin()+1; it!=splitChain.end(); ++it) {
        std::string node = *it;
        
        if (node[0] == 'i') {
          //Logger::debug("is i: ");
        }
        else {
            if (node.back() == '\'') {
                if (! isPrivate) throw std::runtime_error("Invalid chain "+ chainStr+ ",  not private extended key.");

                node = node.substr(0,node.length()-1);
                uint32_t num = std::stoi(node);
                chain.push_back(KeyTree::toPrime(num));
            }
            else {
                uint32_t num = std::stoi(node);
                chain.push_back(num);
            }
        }
    }
    
    return chain;
}


void KeyTree::setTestNet(bool enabled) {
    if (enabled) Coin::HDKeychain::setVersions(0x04358394, 0x043587CF);
    else Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
}

std::string KeyTree::iToString(uint32_t i) {
    std::stringstream ss;
    ss << (0x7fffffff & i);
    if (KeyTree::isPrime(i)) { ss << "'"; }
    return ss.str();
}
    
std::vector<std::string> KeyTree::split(std::string text, char seperator) { //equivalent to python text.split(seperator)
    size_t pos = text.find(seperator);
    size_t initialPos = 0;
    std::vector<std::string> rtn;
    while (pos != std::string::npos)
    {
        rtn.push_back(text.substr(initialPos, pos - initialPos));
        initialPos = pos + 1;
        pos = text.find(seperator, initialPos);
    }
    rtn.push_back(text.substr(initialPos, std::min((int)pos, (int) text.size()) - initialPos));
    return rtn;
}









std::pair<std::string,std::string> KeyTree::generatePrivateKey(const Coin::HDKeychain& keyChain, uint32_t i) {
    if (! keyChain.isPrivate()) throw std::runtime_error("Not private extended key.");
    
    std::pair<uchar_vector,uchar_vector> tmp;
    //std::vector<uint32_t> sequence = {0,0,i};
    std::vector<uint32_t> sequence = {i};
    tmp = KeyTree::vectorTranverseCKD(sequence, keyChain.key(), keyChain.chain_code());
    uchar_vector k = tmp.first.getHex();
    uchar_vector chain = tmp.second;
    
    std::string key = KeyTree::SecretToASecret(k, true);
    
    //Logger::debug("\ni: " + std::to_string(i));
    //Logger::debug("k: " + k.getHex());
    //Logger::debug("chain: " + chain.getHex());
    //Logger::debug("privateKey: " + key);
    
    std::string address = KeyTree::getAddressFromKeyChain(keyChain, i);
    
    return std::pair<std::string,std::string>(key,address);
}


std::string KeyTree::getAddressFromKeyChain(const Coin::HDKeychain& keyChain, uint32_t i) {
    std::pair<uchar_vector,uchar_vector> tmp;
    //std::vector<uint32_t> sequence = {0,0,i};
    std::vector<uint32_t> sequence = {i};
    tmp = KeyTree::vectorTranverseCKD_Prime(sequence, keyChain.pubkey(), keyChain.chain_code());
    uchar_vector K = tmp.first.getHex();
    uchar_vector chain = tmp.second;
    
    //Logger::debug("K: " + K.getHex());
    //Logger::debug("chain: " + chain.getHex());
    
    std::string address = KeyTree::public_key_to_bc_address(K);
    return address;
}



std::pair<std::string,std::string> KeyTree::generateAddress(const Coin::HDKeychain& keyChain, uint32_t i) {
    if (keyChain.isPrivate()) throw std::runtime_error("Not public extended key.");
    
    std::pair<uchar_vector,uchar_vector> tmp;
    //std::vector<uint32_t> sequence = {0,0,i};
    std::vector<uint32_t> sequence = {i};
    tmp = KeyTree::vectorTranverseCKD_Prime(sequence, keyChain.pubkey(), keyChain.chain_code());
    uchar_vector K = tmp.first.getHex();
    uchar_vector chain = tmp.second;
    
    std::string address = KeyTree::public_key_to_bc_address(K);
    return std::pair<std::string,std::string>("",address);
}


std::pair<uchar_vector,uchar_vector> KeyTree::CKD_prime(uchar_vector K, uchar_vector c, uint32_t i) {
    Coin::HDKeychain parentpub(K, c);
    if (parentpub.isPrivate()) throw std::runtime_error("Not public extended key.");
    
    Coin::HDKeychain pub = parentpub.getChild(i);
    uchar_vector K_i(pub.pubkey());
    uchar_vector c_i(pub.chain_code());
    
    //Logger::debug("K_i: " + K_i.getHex());
    //Logger::debug("c_i: " + c_i.getHex());
    
    std::pair<uchar_vector,uchar_vector> ret(K_i, c_i);
    return ret;
}

//CKD(CKD(CKD(m,0x8000003),0x2),0x5) = m/3'/2/5
// CKD(CKD(m,0x8000000),0x8xxxxxx) = m/0'/n'/
std::pair<uchar_vector,uchar_vector> KeyTree::CKD(uchar_vector k, uchar_vector c, uint32_t i) {
    Coin::HDKeychain parentpub(k, c);
    if (! parentpub.isPrivate()) throw std::runtime_error("Not private extended key.");
    
    Coin::HDKeychain pub = parentpub.getChild(i);
    uchar_vector k_i(pub.key());
    uchar_vector c_i(pub.chain_code());
    
    //Logger::debug("k_i: " + k_i.getHex());
    //Logger::debug("c_i: " + c_i.getHex());
    
    std::pair<uchar_vector,uchar_vector> ret(k_i, c_i);
    return ret;
}

#pragma mark public key

uchar_vector KeyTree::hash_160(const uchar_vector public_key) {
    return mdsha(public_key);
}

std::string KeyTree::public_key_to_bc_address(const uchar_vector public_key) {
    uchar_vector h160 = KeyTree::hash_160(public_key);
    //Logger::debug("h160: " + h160.getHex());
    return KeyTree::hash_160_to_bc_address(h160);
}

std::string KeyTree::hash_160_to_bc_address(const uchar_vector h160, int addrtype) {
    uchar_vector vh160;
    
    //vh160.push_back((unsigned char)Python::chr(addrtype)); //TODO: does not work, why?
    vh160.push_back((unsigned char)addrtype);
    
    vh160 += h160;
    //Logger::debug("vh160: " + vh160.getHex());
    
    uchar_vector h = KeyTree::Hash(vh160);
    //Logger::debug("Hash: " + h.getHex());
    
    uchar_vector addr = vh160;
    uchar_vector tmp(h.begin(), h.begin()+4);
    addr += tmp;
    
    //Logger::debug("addrgetHex: " + addr.getHex());
    
    //return toBase58Check(addr);
    return toBase58(addr);
}

#pragma mark private key

uchar_vector KeyTree::Hash(uchar_vector x) {
    return sha256_2(x);
}

std::string KeyTree::EncodeBase58Check(uchar_vector vchIn) {
    uchar_vector hash = KeyTree::Hash(vchIn);
    uchar_vector tmp(hash.begin(), hash.begin()+4);
    uchar_vector ret = vchIn+tmp;
    //Logger::debug("EncodeBase58Check: " + ret.getHex());
    
    //both works, pick one
    //return toBase58Check(ret);
    return toBase58(ret);
}

std::string KeyTree::SecretToASecret(const uchar_vector secret, bool compressed) {
    //Logger::debug("secret: " + secret.getHex());
    uchar_vector vchIn;
    
    vchIn.push_back('\x80');
    //vchIn.push_back((addrtype+128)&255);
    //vchIn.push_back(Python::chr((addrtype+128)&255)); //TODO: does not work, fault with python electrum??
    
    vchIn += secret;
    if (compressed) vchIn.push_back('\01');
    
    //Logger::debug("vchIn: " + vchIn.getHex());
    return EncodeBase58Check(vchIn);
}

std::pair<uchar_vector,uchar_vector> KeyTree::vectorTranverseCKD(std::vector<uint32_t> sequence, uchar_vector k, uchar_vector chain) {
    //Logger::debug("k: " + k.getHex());
    //Logger::debug("chain: " + chain.getHex());
    
    for(auto it=sequence.begin(); it!=sequence.end(); ++it) {
        int i = *it;
        std::pair<uchar_vector,uchar_vector> tmp = CKD(k, chain, i);
        k = tmp.first.getHex().substr(2); //rid leading 0x03
        chain = tmp.second;
        Logger::debug("\ni: " + std::to_string(i));
        Logger::debug("k: " + k.getHex());
        Logger::debug("chain: " + chain.getHex());
    }
    
    return std::pair<uchar_vector,uchar_vector>(k, chain);
}

std::pair<uchar_vector,uchar_vector> KeyTree::vectorTranverseCKD_Prime(std::vector<uint32_t> sequence, uchar_vector k, uchar_vector chain) {
    //Logger::debug("k: " + k.getHex());
    //Logger::debug("chain: " + chain.getHex());
    
    for(auto it=sequence.begin(); it!=sequence.end(); ++it) {
        int i = *it;
        std::pair<uchar_vector,uchar_vector> tmp = CKD_prime(k, chain, i);
        k = tmp.first.getHex();
        chain = tmp.second;
        Logger::debug("\ni: " + std::to_string(i));
        Logger::debug("k: " + k.getHex());
        Logger::debug("chain: " + chain.getHex());
    }
    
    return std::pair<uchar_vector,uchar_vector>(k, chain);
}
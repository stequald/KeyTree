////////////////////////////////////////////////////////////////////////////////
//
// keynode.cpp
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

#include "keynode.h"
#include "CoinClasses/Base58Check.h"
#include "logger.h"

KeyNode::KeyNode(const bytes_t& key, const bytes_t& chain_code, uint32_t child_num, uint32_t parent_fp, uint32_t depth)
: Coin::HDKeychain(key, chain_code, child_num, parent_fp, depth) {}

KeyNode::KeyNode(const bytes_t& extkey) : Coin::HDKeychain(extkey) {}

KeyNode::KeyNode( const KeyNode& other ) {
    valid_ = other.valid_;
    if (!valid_) return;
    
    version_ = other.version_;
    depth_ = other.depth_;
    parent_fp_ = other.parent_fp_;
    child_num_ = other.child_num_;
    chain_code_ = other.chain_code_;
    key_ = other.key_;
    Coin::HDKeychain::updatePubkey();
}

KeyNode KeyNode::getChild(uint32_t i) const {
    KeyNode ret(Coin::HDKeychain::getChild(i).extkey());
    return ret;
}

KeyNode KeyNode::getPublic() const {
    KeyNode ret(Coin::HDKeychain::getPublic().extkey());
    return ret;
}

std::string KeyNode::privkey() const {
    if(this->isPrivate()) {
        uchar_vector k = this->key();
        k = k.getHex().substr(2);
        return KeyNode::secretToASecret(k, true);
    }
    return "";
}

std::string KeyNode::address() const {
    uchar_vector K = this->pubkey();
    return KeyNode::public_key_to_bc_address(K);
}

uchar_vector KeyNode::hash_160(const uchar_vector& public_key) {
    return mdsha(public_key);
}

std::string KeyNode::public_key_to_bc_address(const uchar_vector& public_key) {
    uchar_vector h160 = KeyNode::hash_160(public_key);
    return KeyNode::hash_160_to_bc_address(h160);
}

std::string KeyNode::hash_160_to_bc_address(const uchar_vector& h160, int addrtype) {
    uchar_vector vh160;
    vh160.push_back((unsigned char)addrtype);
    vh160 += h160;
    return toBase58Check(vh160);
}

std::string KeyNode::encodeBase58Check(const uchar_vector& vchIn) {
    return toBase58Check(vchIn);
}

std::string KeyNode::secretToASecret(const uchar_vector& secret, bool compressed) {
    uchar_vector vchIn;
    vchIn.push_back('\x80');
    vchIn += secret;
    if (compressed) vchIn.push_back('\01');
    
    return encodeBase58Check(vchIn);
}

void KeyNode::setTestNet(bool enabled) {
    if (enabled) Coin::HDKeychain::setVersions(0x04358394, 0x043587CF);
    else Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
}
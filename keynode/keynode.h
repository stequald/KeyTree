////////////////////////////////////////////////////////////////////////////////
//
// keynode.h
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

#ifndef KEYNODE_KEYNODE_H
#define KEYNODE_KEYNODE_H

#include <iostream>
#include <vector>
#include "CoinClasses/hdkeys.h"
#include "logger.h"
#include "stringutils.h"

class KeyNodeSeed : public Coin::HDSeed {
public:
    KeyNodeSeed(const bytes_t& seed) : HDSeed(seed) {}
};

class KeyNode : public Coin::HDKeychain {
public:
    KeyNode() {}
    KeyNode(const bytes_t& key, const bytes_t& chain_code, uint32_t child_num = 0, uint32_t parent_fp = 0, uint32_t depth = 0);
    KeyNode(const bytes_t& extkey);
    KeyNode(const KeyNode& other);
    KeyNode getChild(uint32_t i) const;
    KeyNode getPublic() const;
    std::string address() const;
    std::string privkey() const;
    static void setTestNet(bool enabled);
private:
    static std::string secretToASecret(const uchar_vector& secret, bool compressed = false);
    static std::string public_key_to_bc_address(const uchar_vector& public_key);
    static uchar_vector hash_160(const uchar_vector& public_key);
    static std::string hash_160_to_bc_address(const uchar_vector& h160, int addrtype = 0);
    static std::string encodeBase58Check(const uchar_vector& vchIn);
};

#endif /* KEYNODE_KEYNODE_H */

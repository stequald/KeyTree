////////////////////////////////////////////////////////////////////////////////
//
// kt.h
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

#include <iostream>
#include <algorithm>
#include <map>
#include <stdexcept>
#include <sstream>
#include <deque>
#include "keynode/keynode.h"
#include "keynode/logger.h"
#include "keynode/CoinClasses/Base58Check.h"

using namespace std;
typedef std::pair<uint32_t,uint32_t> Range;
typedef std::pair<bool,Range> IsPrivateNPathRange; // < isPrivate, <min,max> >
typedef std::deque<IsPrivateNPathRange> TreeChains;

static const std::string HELP = "help";
static const std::string SEED_FORMAT = "seed_format";

static const std::string SEED = "seed";
static const std::string SEED_HEX = "seed.hex";

static const std::string EXTENDEDKEY = "extkey";
static const std::string CHAIN = "chain";
static const std::string I_MIN = "imin";
static const std::string I_MAX = "imax";

static const std::string TREE_TRAVERSAL_OPTION = "traverse";
static const std::string TREE_TRAVERSAL_TYPE_PREORDER = "preorder";
static const std::string TREE_TRAVERSAL_TYPE_POSTORDER = "postorder";
static const std::string TREE_TRAVERSAL_TYPE_LEVELORDER = "levelorder";

static const std::string SEED_SHORT = "s";
static const std::string SEED_SHORT_HEX_SHORT = "s.h";
static const std::string SEED_HEX_SHORT = "seed.h";
static const std::string SEED_SHORT_HEX = "s.hex";

static const std::string EXTENDEDKEY_SHORT = "ek";
static const std::string CHAIN_SHORT = "c";
static const std::string I_MIN_SHORT = "min";
static const std::string I_MAX_SHORT = "max";

static const std::string TREE_TRAVERSAL_OPTION_SHORT = "trav";
static const std::string TREE_TRAVERSAL_TYPE_PREORDER_SHORT = "pre";
static const std::string TREE_TRAVERSAL_TYPE_POSTORDER_SHORT = "post";
static const std::string TREE_TRAVERSAL_TYPE_LEVELORDER_SHORT = "lev";

static const std::string cmdName = "./kt";
static const std::string exampleArg1 = " -seed \"correct horse battery staple\" -chain \"m/0'/0\"";
static const std::string exampleArg2 = " -seed.hex 000102030405060708090a0b0c0d0e0f -c \"m/0'/0\"";
static const std::string exampleArg3 = " -s.hex 000102030405060708090a0b0c0d0e0f -chain \"m/0'/0\"";
static const std::string exampleArg4 = " -s.h 000102030405060708090a0b0c0d0e0f -c \"m/0'/0\"";
static const std::string exampleArg5 = " -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -c \"m/0'/0\"";
static const std::string exampleArg6 = " -extkey \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" -chain \"m/0/0\"";
static const std::string exampleArg7 = " -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -imin 0 -imax 3";
static const std::string exampleArg8 = " -extkey \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" -min 0 -max 3";

static const std::string exampleArg9 = " -extkey \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\"";
static const std::string exampleArg10 = " -ek \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\"";

static const std::string exampleArg11 = " -seed.hex \"000102030405060708090a0b0c0d0e0f\" -chain \"m/0'/(3-6)'/(1-2)/8\"";
static const std::string exampleArg12 = " -extkey \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -chain \"m/0'/(5-8)'\"";

static const std::string exampleArg13 = " -ek \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" -chain \"m/0/(3-4)/(1-2)\" -traverse levelorder";
static const std::string exampleArg14 = " -seed.hex \"000102030405060708090a0b0c0d0e0f\" -chain \"m/0'/(3-4)'/6'\" -trav postorder";

namespace TreeTraversal {
    enum Type {
        preorder,
        postorder,
        levelorder
    };
}

static const TreeTraversal::Type defaultTreeTraversalType = TreeTraversal::preorder;

void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr, StringUtils::StringFormat seedStringFormat, TreeTraversal::Type traversalType = defaultTreeTraversalType);
void outputExtKeysFromExtKey(const std::string& extKey, const std::string& chainStr, TreeTraversal::Type traversalType = defaultTreeTraversalType);
void outputKeyAddressesFromExtKey(const std::string& extKey, uint32_t i_min = 0, uint32_t i_max = 9);
void outputKeyAddressofExtKey(const std::string& extKey);
void outputString(const std::string& str);
void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName);
void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName);
void traverseLevelorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, uint64_t level = 0, std::deque<KeyNode> keyNodeDeq = std::deque<KeyNode>(), std::deque<std::pair<uint64_t,std::string>> levelNChainDeq = std::deque<std::pair<uint64_t,std::string>>());
void visit(const KeyNode& keyNode, const std::string& chainName);
static TreeChains parseChainString(const std::string& chainStr, bool isPrivate = true);
static std::string iToString(uint32_t i);
uchar_vector extKeyBase58OrHexToBytes(const std::string& extKey);
static uchar_vector fromBase58ExtKey(const std::string& extKey);
static inline uint32_t toPrime(uint32_t i) { return 0x80000000 | i; }
static inline bool isPrime(uint32_t i) { return 0x80000000 & i; }
IsPrivateNPathRange parseRange(const std::string node, bool isPrivate);

void testVector1() {
    outputExtKeysFromSeed("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", StringUtils::hex);
}

void testVector2() {
    std::string seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    outputExtKeysFromSeed(seed, "m/0/2147483647'/1/2147483646'/2", StringUtils::hex);
}

template<typename It>
std::map<std::string, std::string> parse_arguments(It begin, It end) {
    std::map<std::string, std::string> argsDict;
    
    for (auto it = begin ; it != end; ++it) {
        std::string arg = *it;
        if (arg[0] != '-')
        throw std::invalid_argument("Invalid arguments.");
        
        arg = arg.substr(1);
        if (arg == HELP) {
            argsDict[HELP] = HELP;
            break;
        } else if (arg == SEED || arg == SEED_SHORT) {
            ++it;
            argsDict[SEED] = *it;
            argsDict[SEED_FORMAT] = ""; //assumes ascii
        } else if (arg == SEED_HEX || arg == SEED_HEX_SHORT
                   || arg == SEED_SHORT_HEX || arg == SEED_SHORT_HEX_SHORT) {
            ++it;
            argsDict[SEED] = *it;
            argsDict[SEED_FORMAT] = "hex";
        } else if(arg == EXTENDEDKEY || arg == EXTENDEDKEY_SHORT) {
            ++it;
            argsDict[EXTENDEDKEY] = *it;
        } else if(arg == CHAIN || arg == CHAIN_SHORT) {
            ++it;
            argsDict[CHAIN] = *it;
        } else if(arg == I_MIN || arg == I_MIN_SHORT) {
            ++it;
            argsDict[I_MIN] = *it;
        } else if(arg == I_MAX || arg == I_MAX_SHORT) {
            ++it;
            argsDict[I_MAX] = *it;
        } else if(arg == TREE_TRAVERSAL_OPTION || arg == TREE_TRAVERSAL_OPTION_SHORT) {
            ++it;
            argsDict[TREE_TRAVERSAL_OPTION] = *it;
        } else {
            throw std::invalid_argument("Invalid arguments.");
        }
    }
    
    return argsDict;
}

void outputExamples() {
    outputString("Input parameters can be in hex or base58.");
    outputString("Here are some examples:");
    outputString("");
    
    outputString("Given Seed and Chain will output Child Extended Keys:");
    outputString(cmdName+exampleArg1);
    outputString(cmdName+exampleArg2);
    outputString(cmdName+exampleArg3);
    outputString(cmdName+exampleArg4);
    outputString("");
    
    outputString("Given Extended Key and Chain will output Child Extended Keys:");
    outputString(cmdName+exampleArg5);
    outputString(cmdName+exampleArg6);
    outputString("");
    
    outputString("Given Extended Key and range will output Private Keys and Addresses from child of Extended Key in given range:");
    outputString(cmdName+exampleArg7);
    outputString(cmdName+exampleArg8);
    outputString("");
    
    outputString("Given Extended Key will output Private Key and Address of Extended Key:");
    outputString(cmdName+exampleArg9);
    outputString(cmdName+exampleArg10);
    outputString("");

    outputString("It is also possible to have multiple chain paths:");
    outputString(cmdName+exampleArg11);
    outputString(cmdName+exampleArg12);

    outputString("It is also possible to output the Extended Keys in a different order:");
    outputString(cmdName+exampleArg13);
    outputString(cmdName+exampleArg14);

}

TreeTraversal::Type getTreeTraversalOption(std::string treeTraversalOption) {
    if (treeTraversalOption == TREE_TRAVERSAL_TYPE_LEVELORDER
        || treeTraversalOption == TREE_TRAVERSAL_TYPE_LEVELORDER_SHORT)
        return TreeTraversal::levelorder;
    else if (treeTraversalOption == TREE_TRAVERSAL_TYPE_POSTORDER
        || treeTraversalOption == TREE_TRAVERSAL_TYPE_POSTORDER_SHORT)
        return TreeTraversal::postorder;
    else if (treeTraversalOption == TREE_TRAVERSAL_TYPE_PREORDER
             || treeTraversalOption == TREE_TRAVERSAL_TYPE_PREORDER)
        return TreeTraversal::preorder;
    else
        return defaultTreeTraversalType;
}

int handle_arguments(std::map<std::string, std::string> argsDict) {
    Logger::debug("Arguments:");
    for (auto it = argsDict.begin(); it != argsDict.end(); ++it) {
        Logger::debug("\tkey: " + it->first + " value: " + it->second);
    }
    Logger::debug("");
    if (argsDict[HELP] == HELP) {
        outputExamples();
        return 0;
    } else if (argsDict[SEED] != "" && argsDict[CHAIN] != "") {
        std::string seed = argsDict[SEED];
        std::string chain = argsDict[CHAIN];
        
        StringUtils::StringFormat seed_format;
        if (argsDict[SEED_FORMAT] == "hex")
        seed_format = StringUtils::hex;
        else
        seed_format = StringUtils::ascii;
        
        outputExtKeysFromSeed(seed, chain, seed_format, getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]));
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[CHAIN] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        std::string chain = argsDict[CHAIN];
        
        outputExtKeysFromExtKey(extkey, chain, getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]));
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[I_MIN] != "" && argsDict[I_MAX] != "") {

        std::string extkey = argsDict[EXTENDEDKEY];
        uint32_t i_min = std::stoi(argsDict[I_MIN]);
        uint32_t i_max = std::stoi(argsDict[I_MAX]);
        outputKeyAddressesFromExtKey(extkey, i_min, i_max);
    } else if (argsDict[EXTENDEDKEY] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        outputKeyAddressofExtKey(extkey);
    } else {
        throw std::invalid_argument("Invalid arguments.");
    }
    
    return 0;
}



int main(int argc, const char * argv[]) {
    Logger::setLogLevelError();
    Logger::setLogLevelDebug();
    //KeyNode::setTestNet(true);

    //testVector1();
    //testVector2();
    
    try {
        std::map<std::string, std::string> argsDict = parse_arguments(argv+1, argv+argc);
        return handle_arguments(argsDict);
    }
    catch (const std::invalid_argument& err) {
        outputString("Error: " + std::string(err.what()));
        outputString("---------------------------------------------------");
        outputExamples();
    }
    catch (const std::runtime_error& err) {
        outputString("Error: " + std::string(err.what()));
    }
}



void outputString(const std::string& str) {
    Logger::log(str);
}

uchar_vector extKeyBase58OrHexToBytes(const std::string& extKey) {
    uchar_vector extendedKey;
    if (isBase58CheckValid(extKey))
        extendedKey = fromBase58ExtKey(extKey);
    else if (StringUtils::isHex(extKey))
        extendedKey = uchar_vector(extKey);
    else
        throw std::runtime_error("Invalid extended key. Extended key must be in base58 or hex form.");
    
    return extendedKey;
}

void visit(const KeyNode& keyNode, const std::string& chainName) {
    outputString("* [Chain " + chainName + "]");
    if (keyNode.isPrivate()) {
        KeyNode keyNodePub= keyNode.getPublic();
        outputString("  * ext pub: " + toBase58Check(keyNodePub.extkey()));
        outputString("  * ext prv: " + toBase58Check(keyNode.extkey()));
        //outputString("  * priv key: " + keyNode.privkey());
        //outputString("  * address: " + keyNode.address());
    } else {
        outputString("  * ext pub: " + toBase58Check(keyNode.extkey()));
        //outputString("  * address: " + keyNode.address());
    }
}

void traverseLevelorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, uint64_t level, std::deque<KeyNode> keyNodeDeq, std::deque<std::pair<uint64_t,std::string>> levelNChainDeq) {
    if (level < treeChains.size()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.at(level);
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        
        level++;
        for (uint32_t i = min; i <= max; ++i) {
            uint32_t k = i;
            if (isPrivate) k = toPrime(k);
            std::string childChainName = chainName + "/" + iToString(k);
            KeyNode childNode = keyNode.getChild(k);
    
            keyNodeDeq.push_back(childNode);
            levelNChainDeq.push_back(std::pair<uint64_t,std::string>(level,childChainName));
        }
    }

    visit(keyNode, chainName);
    
    if (! keyNodeDeq.empty()) {
        std::pair<uint64_t,std::string> pair = levelNChainDeq.front();
        uint64_t lev = pair.first++;
        std::string cc = pair.second;
        KeyNode node = keyNodeDeq.front();
        keyNodeDeq.pop_front();
        levelNChainDeq.pop_front();
        traverseLevelorder(node, treeChains, cc, lev, keyNodeDeq, levelNChainDeq);
    }
}

void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;

        for (uint32_t i = min; i <= max; ++i) {
            uint32_t k = i;
            if (isPrivate) k = toPrime(k);
            std::string childChainName = chainName + "/" + iToString(k);
            KeyNode childNode = keyNode.getChild(k);
            visit(childNode, childChainName);
            traversePreorder(childNode, treeChains, childChainName);
        }
    }
}

void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        
        for (uint32_t i = min; i <= max; ++i) {
            uint32_t k = i;
            if (isPrivate) k = toPrime(k);
            std::string childChainName = chainName + "/" + iToString(k);
            KeyNode childNode = keyNode.getChild(k);
            traversePostorder(childNode, treeChains, childChainName);
            visit(childNode, childChainName);
        }
    }
}

void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr, StringUtils::StringFormat seedStringFormat, TreeTraversal::Type traversalType) {
    std::string seedHex;
    if (seedStringFormat == StringUtils::ascii) {
        seedHex = StringUtils::string_to_hex(seed);
        
    } else if (seedStringFormat == StringUtils::hex) {
        if (! StringUtils::isHex(seed))
            throw std::runtime_error("Invalid hex string \"" + seed + "\"");
        
        seedHex = seed;
    } else throw std::runtime_error("Invalid seed string format.");
    
    KeyNodeSeed keyNodeSeed((uchar_vector(seedHex)));
    bytes_t k = keyNodeSeed.getMasterKey();
    bytes_t c = keyNodeSeed.getMasterChainCode();
    KeyNode prv(k, c);
    KeyNode pub = prv.getPublic();
    outputString("Master (hex): " + seedHex);
    outputString("* [Chain m]");
    outputString("  * ext pub: " + toBase58Check(pub.extkey()));
    outputString("  * ext prv: " + toBase58Check(prv.extkey()));
    TreeChains treeChains = parseChainString(chainStr, prv.isPrivate());
    if (traversalType == TreeTraversal::postorder)
        traversePostorder(prv, treeChains, "m");
    else if (traversalType == TreeTraversal::levelorder)
        traverseLevelorder(prv, treeChains, "m");
    else
        traversePreorder(prv, treeChains, "m");
}

void outputExtKeysFromExtKey(const std::string& extKey, const std::string& chainStr, TreeTraversal::Type traversalType) {
    uchar_vector extendedKey(extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    TreeChains treeChains = parseChainString(chainStr, keyNode.isPrivate());
    if (traversalType == TreeTraversal::postorder)
        traversePostorder(keyNode, treeChains, "m");
    else if (traversalType == TreeTraversal::levelorder)
        traverseLevelorder(keyNode, treeChains, "m");
    else
        traversePreorder(keyNode, treeChains, "m");
}

void outputKeyAddressesFromExtKey(const std::string& extKey, uint32_t i_min, uint32_t i_max) {
    uchar_vector extendedKey(extKeyBase58OrHexToBytes(extKey));
    
    KeyNode keyNode(extendedKey);
    for (uint32_t i = i_min; i < i_max; i++ ) {
        KeyNode child = keyNode.getChild(i);
        if (child.isPrivate()) outputString("  * priv key: " + child.privkey());
        outputString("  * address: " + child.address());
        outputString("");
    }
}

void outputKeyAddressofExtKey(const std::string& extKey) {
    uchar_vector extendedKey(extKeyBase58OrHexToBytes(extKey));
    
    KeyNode keyNode(extendedKey);
    if (keyNode.isPrivate()) {
        KeyNode keyNodePub= keyNode.getPublic();
        outputString("  * ext pub: " + toBase58Check(keyNodePub.extkey()));
        outputString("  * ext prv: " + toBase58Check(keyNode.extkey()));
        outputString("  * priv key: " + keyNode.privkey());
        outputString("  * address: " + keyNodePub.address());
    } else {
        outputString("  * ext pub: " + toBase58Check(keyNode.extkey()));
        outputString("  * address: " + keyNode.address());
    }
    outputString("");
}


uchar_vector fromBase58ExtKey(const std::string& extKey) {
    static unsigned int dummy = 0;
    uchar_vector fillKey;
    fromBase58Check(extKey, fillKey, dummy);
    static const std::string VERSION_BYTE("04");
    return uchar_vector(VERSION_BYTE+fillKey.getHex()); //append VERSION_BYTE to begining
}

TreeChains parseChainString(const std::string& chainStr, bool isPrivate) {
    TreeChains treeChains;
    
    const std::string s = StringUtils::split(chainStr)[0]; //trim trailing whitespaces
    
    std::vector<std::string> splitChain = StringUtils::split(s, '/');
    
    if (splitChain[0] != "m")
        throw std::runtime_error("Invalid Chain string.");
    
    if (splitChain.back() == "") splitChain.pop_back(); // happens if chainStr has '/' at end
    
    for(auto it=splitChain.begin()+1; it!=splitChain.end(); ++it) {
        std::string node = *it;
        if (node.back() == '\'') {
            if (! isPrivate) throw std::runtime_error("Invalid chain "+ chainStr+ ",  not private extended key.");
            
            node = node.substr(0,node.length()-1);
            if (node.front() == '(' && node.back() == ')') {
                IsPrivateNPathRange range = parseRange(node, true);
                treeChains.push_back(range);
            } else {
                uint32_t num = toPrime(std::stoi(node));
                treeChains.push_back(IsPrivateNPathRange(true , Range(num, num)));
            }
        } else {
            if (node.front() == '(' && node.back() == ')') {
                IsPrivateNPathRange range = parseRange(node, false);
                treeChains.push_back(range);
            } else {
                uint32_t num = std::stoi(node);
                treeChains.push_back(IsPrivateNPathRange(false , Range(num, num)));
            }
        }
    }
    
    return treeChains;
}

IsPrivateNPathRange parseRange(const std::string node, bool isPrivate) {
    //node must be like (123-9345)
    const std::string minMaxString =  node.substr(1,node.length()-2);
    const std::vector<std::string> minMaxPair = StringUtils::split(minMaxString, '-');
    
    if (minMaxPair.size() != 2)
        throw std::invalid_argument("Invalid arguments.");

    uint32_t min = std::stoi(minMaxPair[0]);
    uint32_t max = std::stoi(minMaxPair[1]);
    if (isPrivate) {
        return IsPrivateNPathRange(true, Range(min, max));
    } else {
        return IsPrivateNPathRange(false, Range(min, max));
    }

}

std::string iToString(uint32_t i) {
    std::stringstream ss;
    ss << (0x7fffffff & i);
    if (isPrime(i)) { ss << "'"; }
    return ss.str();
}


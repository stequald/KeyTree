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
#include "typedefs.h"
#include "keytreeutil.h"

using namespace std;

static const std::string HELP = "-help";
static const std::string SEED_FORMAT = "seed_format";

static const std::string SEED = "-seed";
static const std::string SEED_HEX = "-seed.hex";
static const std::string EXTENDEDKEY = "-extkey";
static const std::string CHAIN = "-chain";
static const std::string TREE_TRAVERSAL_OPTION = "-traverse";
static const std::string TREE_TRAVERSAL_TYPE_PREORDER = "-preorder";
static const std::string TREE_TRAVERSAL_TYPE_POSTORDER = "-postorder";
static const std::string TREE_TRAVERSAL_TYPE_LEVELORDER = "-levelorder";
static const std::string VERBOSE_OPTION = "-verbose";

static const std::string SEED_SHORT = "s";
static const std::string SEED_SHORT_HEX_SHORT = "s.h";
static const std::string SEED_HEX_SHORT = "seed.h";
static const std::string SEED_SHORT_HEX = "s.hex";

static const std::string EXTENDEDKEY_SHORT = "ek";
static const std::string CHAIN_SHORT = "c";
static const std::string TREE_TRAVERSAL_OPTION_SHORT = "trav";
static const std::string TREE_TRAVERSAL_TYPE_PREORDER_SHORT = "pre";
static const std::string TREE_TRAVERSAL_TYPE_POSTORDER_SHORT = "post";
static const std::string TREE_TRAVERSAL_TYPE_LEVELORDER_SHORT = "lev";
static const std::string VERBOSE_OPTION_SHORT = "v";

static const std::string cmdName = "./kt";
static const std::string exampleArg1 = " --seed \"correct horse battery staple\" --chain \"m/0'/0\"";
static const std::string exampleArg2 = " --seed.hex 000102030405060708090a0b0c0d0e0f -c \"m/0'/0\"";
static const std::string exampleArg3 = " -s.hex 000102030405060708090a0b0c0d0e0f --chain \"m/0'/0\"";
static const std::string exampleArg4 = " -s.h 000102030405060708090a0b0c0d0e0f -c \"m/0'/0\"";
static const std::string exampleArg5 = " -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -c \"m/0'/0\"";
static const std::string exampleArg6 = " --extkey \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" --chain \"m/0/0\"";

static const std::string exampleArg7 = " --extkey \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\"";
static const std::string exampleArg8 = " -ek \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\"";

static const std::string exampleArg9 = " --seed.hex \"000102030405060708090a0b0c0d0e0f\" -chain \"m/0'/(3-6)'/(1-2)/8\"";
static const std::string exampleArg10 = " --extkey \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" --chain \"m/0'/(5-8)'\"";

static const std::string exampleArg11 = " -ek \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" --chain \"m/0/(3-4)/(1-2)\" --traverse levelorder";
static const std::string exampleArg12 = " --seed.hex \"000102030405060708090a0b0c0d0e0f\" --chain \"m/0'/(3-4)'/6'\" -trav postorder";

static const std::string exampleArg13 = " --verbose -s.h \"000102030405060708090a0b0c0d0e0f\" --chain \"m/0'/(3-4)'/6'\"";
static const std::string exampleArg14 = " -v -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\"";

namespace TreeTraversal {
    enum Type {
        preorder,
        postorder,
        levelorder
    };
}

static const TreeTraversal::Type defaultTreeTraversalType = TreeTraversal::preorder;


void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr, StringUtils::StringFormat seedStringFormat, TreeTraversal::Type traversalType = defaultTreeTraversalType, const bool isVerbose = false);
void outputExtKeysFromExtKey(const std::string& extKey, const std::string& chainStr, TreeTraversal::Type traversalType = defaultTreeTraversalType, const bool isVerbose = false);
void outputKeyAddressofExtKey(const std::string& extKey, const bool isVerbose = false);
void outputString(const std::string& str);
void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, const bool isVerbose = false);
void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, const bool isVerbose = false);
void traverseLevelorder(const KeyNode& keyNode, const TreeChains& treeChains, const std::string& chainName,
                        uint64_t level, std::deque<KeyNode>& keyNodeDeq,
                        std::deque<std::pair<uint64_t,std::string>>& levelNChainDeq,
                        bool isVerbose = false);
void visit(const KeyNode& keyNode, const std::string& chainName, const bool isVerbose = false);
void outputExtraKeyNodeData(const KeyNode& keyNode);


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
        } else if(arg == TREE_TRAVERSAL_OPTION || arg == TREE_TRAVERSAL_OPTION_SHORT) {
            ++it;
            argsDict[TREE_TRAVERSAL_OPTION] = *it;
        } else if(arg == VERBOSE_OPTION || arg == VERBOSE_OPTION_SHORT) {
            argsDict[VERBOSE_OPTION] = "Y";
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
    
    outputString("Given Extended Key will output Private Key and Address of Extended Key:");
    outputString(cmdName+exampleArg7);
    outputString(cmdName+exampleArg8);
    outputString("");

    outputString("It is also possible to have multiple chain paths:");
    outputString(cmdName+exampleArg9);
    outputString(cmdName+exampleArg10);
    outputString("");

    outputString("It is also possible to output the Extended Keys in a different order:");
    outputString(cmdName+exampleArg11);
    outputString(cmdName+exampleArg12);
    outputString("");

    outputString("For more info on nodes use the verbose option:");
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

bool getIsVerbose(std::string verboseOption) {
    if (verboseOption == "Y") return true;
    else return false;
}

int handle_arguments(std::map<std::string, std::string> argsDict) {
    Logger::debug("Arguments:");
    for (auto arg : argsDict) {
        Logger::debug("\tkey: " + arg.first + " value: " + arg.second);
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
        
        bool isVerbose = getIsVerbose(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        outputExtKeysFromSeed(seed, chain, seed_format, traverseType, isVerbose);
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[CHAIN] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        std::string chain = argsDict[CHAIN];
        
        bool isVerbose = getIsVerbose(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        outputExtKeysFromExtKey(extkey, chain, traverseType, isVerbose);
    } else if (argsDict[EXTENDEDKEY] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        bool isVerbose = getIsVerbose(argsDict[VERBOSE_OPTION]);
        outputKeyAddressofExtKey(extkey, isVerbose);
    } else {
        throw std::invalid_argument("Invalid arguments.");
    }
    
    return 0;
}

void outputString(const std::string& str) {
    Logger::log(str);
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

void visit(const KeyNode& keyNode, const std::string& chainName, const bool isVerbose) {
    outputString("* [Chain " + chainName + "]");
    if (keyNode.isPrivate()) {
        KeyNode keyNodePub= keyNode.getPublic();
        outputString("  * ext pub:  " + toBase58Check(keyNodePub.extkey()));
        outputString("  * ext prv:  " + toBase58Check(keyNode.extkey()));
        outputString("  * priv key: " + keyNode.privkey());
        outputString("  * address:  " + keyNode.address());
        if (isVerbose) {
            outputString("  * pub key:  " + toBase58Check(keyNode.pubkey()));
        }
    } else {
        outputString("  * ext pub:  " + toBase58Check(keyNode.extkey()));
        outputString("  * address:  " + keyNode.address());
        if (isVerbose) {
            outputString("  * pub key:  " + toBase58Check(keyNode.pubkey()));
        }
    }
}

void traverseLevelorder(const KeyNode& keyNode, const TreeChains& treeChains, const std::string& chainName,
                        uint64_t level, std::deque<KeyNode>& keyNodeDeq,
                        std::deque<std::pair<uint64_t,std::string>>& levelNChainDeq,
                        bool isVerbose) {
    if (level < treeChains.size()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.at(level);
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        
        level++;
        for (uint32_t i = min; i <= max; ++i) {
            uint32_t k = i;
            if (isPrivate) k = KeyTreeUtil::toPrime(k);
            std::string childChainName = chainName + "/" + KeyTreeUtil::iToString(k);
            KeyNode childNode = keyNode.getChild(k);
    
            keyNodeDeq.push_back(childNode);
            levelNChainDeq.push_back(std::pair<uint64_t,std::string>(level,childChainName));
        }
    }

    visit(keyNode, chainName, isVerbose);
    
    if (! keyNodeDeq.empty()) {
        std::pair<uint64_t,std::string> pair = levelNChainDeq.front();
        uint64_t lev = pair.first++;
        std::string cc = pair.second;
        KeyNode node = keyNodeDeq.front();
        keyNodeDeq.pop_front();
        levelNChainDeq.pop_front();
        traverseLevelorder(node, treeChains, cc, lev, keyNodeDeq, levelNChainDeq, isVerbose);
    }
}

void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, const bool isVerbose) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        
        if (min == KeyTreeUtil::NODE_IDX_M && max == KeyTreeUtil::NODE_IDX_M) {
            visit(keyNode, "m", isVerbose);
            traversePreorder(keyNode, treeChains, chainName, isVerbose);
        } else {
            for (uint32_t i = min; i <= max; ++i) {
                uint32_t k = i;
                if (isPrivate) k = KeyTreeUtil::toPrime(k);
                std::string childChainName = chainName + "/" + KeyTreeUtil::iToString(k);
                KeyNode childNode = keyNode.getChild(k);
                visit(childNode, childChainName, isVerbose);
                traversePreorder(childNode, treeChains, childChainName, isVerbose);
            }
        }
    }
}

void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName, const bool isVerbose) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        
        if (min == KeyTreeUtil::NODE_IDX_M && max == KeyTreeUtil::NODE_IDX_M) {
            traversePostorder(keyNode, treeChains, chainName, isVerbose);
            visit(keyNode, "m", isVerbose);
        } else {
            for (uint32_t i = min; i <= max; ++i) {
                uint32_t k = i;
                if (isPrivate) k = KeyTreeUtil::toPrime(k);
                std::string childChainName = chainName + "/" + KeyTreeUtil::iToString(k);
                KeyNode childNode = keyNode.getChild(k);
                traversePostorder(childNode, treeChains, childChainName, isVerbose);
                visit(childNode, childChainName, isVerbose);
            }
        }
    }
}

void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr,
                           StringUtils::StringFormat seedStringFormat, TreeTraversal::Type traversalType,
                           bool isVerbose) {
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
    TreeChains treeChains = KeyTreeUtil::parseChainString(chainStr, prv.isPrivate());
    outputString("Master (hex): " + seedHex);
    
    if (traversalType == TreeTraversal::postorder)
        traversePostorder(prv, treeChains, "m", isVerbose);
    else if (traversalType == TreeTraversal::levelorder) {
        treeChains.pop_front();
        std::deque<KeyNode> KeyNodeDeq;
        std::deque<std::pair<uint64_t,std::string>> levelNChainDeq;
        traverseLevelorder(prv, treeChains, "m", 0, KeyNodeDeq, levelNChainDeq, isVerbose);
    }
    else
        traversePreorder(prv, treeChains, "m", isVerbose);
}

void outputExtraKeyNodeData(const KeyNode& keyNode) {
    outputString("  * depth:              " + std::to_string(keyNode.depth()));
    uint32_t childNum = keyNode.child_num();
    if (KeyTreeUtil::isPrime(childNum))
        outputString("  * child number:       " + std::to_string(KeyTreeUtil::removePrime(childNum))+"'");
    else
        outputString("  * child number:       " + std::to_string(childNum));
    std::stringstream stream;
    stream << std::hex << keyNode.parent_fp();
    std::string parent_fp(stream.str());
    outputString("  * parent fingerprint: " + parent_fp);
    std::stringstream stream2;
    stream2 << std::hex << keyNode.fp();
    std::string fp(stream2.str());
    outputString("  * fingerprint:        " + fp);
}

void outputExtKeysFromExtKey(const std::string& extKey, const std::string& chainStr,
                             TreeTraversal::Type traversalType, const bool isVerbose) {
    uchar_vector extendedKey(KeyTreeUtil::extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    TreeChains treeChains = KeyTreeUtil::parseChainString(chainStr, keyNode.isPrivate());
    
    if (isVerbose) outputExtraKeyNodeData(keyNode);

    if (traversalType == TreeTraversal::postorder)
        traversePostorder(keyNode, treeChains, "___", isVerbose);
    else if (traversalType == TreeTraversal::levelorder) {
        treeChains.pop_front();
        std::deque<KeyNode> KeyNodeDeq;
        std::deque<std::pair<uint64_t,std::string>> levelNChainDeq;
        traverseLevelorder(keyNode, treeChains, "___", 0, KeyNodeDeq, levelNChainDeq, isVerbose);
    } else
        traversePreorder(keyNode, treeChains, "___", isVerbose);
}

void outputKeyAddressofExtKey(const std::string& extKey, const bool isVerbose) {
    uchar_vector extendedKey(KeyTreeUtil::extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    visit(keyNode, "___", isVerbose);
    if (isVerbose) outputExtraKeyNodeData(keyNode);
    outputString("");
}


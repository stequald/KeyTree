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
#include <stdexcept>
#include <sstream>
#include <deque>
#include <termios.h>
#include <unistd.h>
#include "keynode/keynode.h"
#include "keynode/logger.h"
#include "keynode/CoinClasses/Base58Check.h"
#include "keytreeutil.h"

using namespace std;

/*
 Option to specify seed, extended key and chain in command line is possible,
 but is discouraged because on most OS commands are stored in a history file.
 To do it put the noprompt option at the begining.
 ./kt --noprompt -s "this is a password" --chain "m/(0-1)'/(6-8)'" -trav levelorder
 ./kt -np --extkey "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" -c "m/(0-1)'/8"
*/

static bool noInputEcho = false;
static const std::string NO_INPUT_ECHO = "-noecho";
static const std::string NO_INPUT_ECHO_SHORT = "ne";

static const std::string NO_PROMPT = "-noprompt";
static const std::string NO_PROMPT_SHORT = "np";

static const std::string cmdName = "./kt";
static const std::string HELP = "-help";
static const std::string SEED_FORMAT = "seed_format";
static const std::string SEED_VALUE = "seed_value";
static const std::string EXTENDEDKEY_VALUE = "extkey_value";
static const std::string CHAIN_VALUE = "chain_value";

static const std::string SEED = "-seed";
static const std::string SEED_HEX = "-seed.hex";
static const std::string EXTENDEDKEY = "-extkey";
static const std::string CHAIN = "-chain";
static const std::string TREE_TRAVERSAL_OPTION = "-traverse";
static const std::string TREE_TRAVERSAL_TYPE_PREORDER = "preorder";
static const std::string TREE_TRAVERSAL_TYPE_POSTORDER = "postorder";
static const std::string TREE_TRAVERSAL_TYPE_LEVELORDER = "levelorder";
static const std::string OUTPUT_ENTIRE_CHAIN_OPTION = "-all";
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
static const std::string OUTPUT_ENTIRE_CHAIN_OPTION_SHORT = "a";
static const std::string VERBOSE_OPTION_SHORT = "v";

static const TreeTraversal::Type defaultTreeTraversalType = TreeTraversal::preorder;

void testVector1();
void testVector2();
template<typename It>
std::map<std::string, std::string> parse_arguments(It begin, It end);
void outputExamples();
TreeTraversal::Type getTreeTraversalOption(std::string treeTraversalOption);
bool getOptionValue(std::string option);
std::string get_input(std::string pretext);
int enter_prompt(std::map<std::string, std::string> argsDict);
int handle_arguments(std::map<std::string, std::string> argsDict);
void outputString(const std::string& str);

void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr,
                           StringUtils::StringFormat seedStringFormat,
                           const OptionsDict& optionsDict = OptionsDict(),
                           TreeTraversal::Type traversalType = defaultTreeTraversalType);
void outputExtKeysFromExtKey(const std::string& extKey, const std::string& chainStr,
                             const OptionsDict& optionsDict = OptionsDict(),
                             TreeTraversal::Type traversalType = defaultTreeTraversalType);
void outputKeyAddressofExtKey(const std::string& extKey,
                              const OptionsDict& optionsDict = OptionsDict());
void outputString(const std::string& str);
void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName,
                      const OptionsDict& optionsDict = OptionsDict());
void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName,
                       const OptionsDict& optionsDict = OptionsDict());
void traverseLevelorder(const KeyNode& keyNode, const TreeChains& treeChains, const std::string& chainName,
                        uint64_t level, std::deque<KeyNode>& keyNodeDeq,
                        std::deque<std::pair<uint64_t,std::string>>& levelNChainDeq,
                        const OptionsDict& optionsDict = OptionsDict());
void visit(const KeyNode& keyNode, const std::string& chainName, const bool isLeafNode,
           const OptionsDict& optionsDict = OptionsDict());
void outputExtraKeyNodeData(const KeyNode& keyNode);


void testVector1() {
    OptionsDict optionsDict;
    optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = true;
    optionsDict[VERBOSE_OPTION] = false;
    outputExtKeysFromSeed("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", StringUtils::hex, optionsDict);
}

void testVector2() {
    OptionsDict optionsDict;
    optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = true;
    optionsDict[VERBOSE_OPTION] = false;
    std::string seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    outputExtKeysFromSeed(seed, "m/0/2147483647'/1/2147483646'/2", StringUtils::hex, optionsDict);
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
            argsDict[SEED_FORMAT] = ""; //assumes ascii
            argsDict[SEED] = "Y";
            if (getOptionValue(argsDict[NO_PROMPT])) {
                ++it;
                argsDict[SEED_VALUE] = *it;
            }
        } else if (arg == SEED_HEX || arg == SEED_HEX_SHORT
                   || arg == SEED_SHORT_HEX || arg == SEED_SHORT_HEX_SHORT) {
            argsDict[SEED_FORMAT] = "hex";
            argsDict[SEED] = "Y";
            if (getOptionValue(argsDict[NO_PROMPT])) {
                ++it;
                argsDict[SEED_VALUE] = *it;
            }
        } else if(arg == EXTENDEDKEY || arg == EXTENDEDKEY_SHORT) {
            argsDict[EXTENDEDKEY] = "Y";
            
            if (getOptionValue(argsDict[NO_PROMPT])) {
                ++it;
                argsDict[EXTENDEDKEY_VALUE] = *it;
            }
        } else if(arg == CHAIN || arg == CHAIN_SHORT) {
            if (getOptionValue(argsDict[NO_PROMPT])) {
                ++it;
                argsDict[CHAIN_VALUE] = *it;
            }
        } else if(arg == TREE_TRAVERSAL_OPTION || arg == TREE_TRAVERSAL_OPTION_SHORT) {
            ++it;
            argsDict[TREE_TRAVERSAL_OPTION] = *it;
            argsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = "Y";
        } else if(arg == OUTPUT_ENTIRE_CHAIN_OPTION || arg == OUTPUT_ENTIRE_CHAIN_OPTION_SHORT) {
            argsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = "Y";
        } else if(arg == VERBOSE_OPTION || arg == VERBOSE_OPTION_SHORT) {
            argsDict[VERBOSE_OPTION] = "Y";
        } else if(arg == NO_INPUT_ECHO || arg == NO_INPUT_ECHO_SHORT) {
            noInputEcho = true;
        } else if(arg == NO_PROMPT || arg == NO_PROMPT_SHORT) {
            argsDict[NO_PROMPT] = "Y";
        } else {
            throw std::invalid_argument("Invalid arguments.");
        }
    }
    
    //default to seed if no option provided
    if (argsDict.find(EXTENDEDKEY) == argsDict.end() && argsDict.find(SEED) == argsDict.end()) {
        argsDict[SEED] = "Y";
    }
    
    return argsDict;
}

void outputExamples() {
    outputString("Extended Keys can be in hex or base58. Seed can be in ASCII or hex. Examples below.");
    outputString("");
    
    outputString("To use KeyTree simply do the following:");
    outputString(cmdName);
    outputString("Enter Seed:");
    outputString("correct horse battery staple");
    outputString("Enter Chain:");
    outputString("m/0'/0");
    outputString("");
    
    outputString("Use the hex option to enter the seed in hex:");
    outputString(cmdName+" --seed.hex");
    outputString("Enter Seed in Hex:");
    outputString("000102030405060708090a0b0c0d0e0f");
    outputString("Enter Chain:");
    outputString("m/0'/0");
    outputString("");

    outputString("Use the extended key option to enter the extended key in lieu of the seed:");
    outputString(cmdName+" --extkey");
    outputString(cmdName+" -ek");
    outputString("");

    outputString("It is also possible to print multiple chain paths together:");
    outputString(cmdName);
    outputString("Enter Extended Key:");
    outputString("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
    outputString("Enter Chain:");
    outputString("m/0'/(3-6)'/(1-2)/8");
    outputString("");

    outputString("To output all the node data on the chain, use the all option:");
    outputString(cmdName+" --all");
    outputString(cmdName+" -a");
    outputString("");

    outputString("It is also possible to output the nodes in a different order:");
    outputString(cmdName+" --traverse levelorder");
    outputString(cmdName+" -trav postorder");
    outputString(cmdName+" -trav preorder");
    outputString("");
    
    outputString("For more information on the node use the verbose option:");
    outputString(cmdName+" --verbose");
    outputString(cmdName+" -v");
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

bool getOptionValue(std::string option) {
    if (option == "Y") return true;
    else return false;
}

std::string get_input(std::string pretext) {
    if (! pretext.empty())
        outputString(pretext);

    std::string buffer;
    std::getline(std::cin, buffer);
    return buffer;
}

int enter_prompt(std::map<std::string, std::string> argsDict) {
    if (argsDict[HELP] == HELP) {
        outputExamples();
    } else if (getOptionValue(argsDict[SEED])) {
        std::string seed;
        std::string chain;
        
        StringUtils::StringFormat seed_format;
        if (argsDict[SEED_FORMAT] == "hex") {
            seed_format = StringUtils::hex;
            seed = get_input("Enter Seed in Hex:");
            if (! StringUtils::isHex(seed))
                throw std::runtime_error("Invalid hex string \"" + seed + "\"");
        } else {
            seed_format = StringUtils::ascii;
            seed = get_input("Enter Seed:");
        }

        chain = get_input("Enter Chain:");
        
        OptionsDict optionsDict;
        optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = getOptionValue(argsDict[OUTPUT_ENTIRE_CHAIN_OPTION]);
        optionsDict[VERBOSE_OPTION] = getOptionValue(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        outputExtKeysFromSeed(seed, chain, seed_format, optionsDict, traverseType);
        
    } else if (getOptionValue(argsDict[EXTENDEDKEY])) {
        std::string extkey;
        std::string chain;
        
        extkey = get_input("Enter Extended Key:");
        
        chain = get_input("Enter Chain:");

        OptionsDict optionsDict;
        optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = getOptionValue(argsDict[OUTPUT_ENTIRE_CHAIN_OPTION]);
        optionsDict[VERBOSE_OPTION] = getOptionValue(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        if(! chain.empty())
            outputExtKeysFromExtKey(extkey, chain, optionsDict, traverseType);
        else
            outputKeyAddressofExtKey(extkey, optionsDict);
    }
    return 0;
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
    } else if (argsDict[SEED_VALUE] != "" && argsDict[CHAIN_VALUE] != "") {
        std::string seed = argsDict[SEED_VALUE];
        std::string chain = argsDict[CHAIN_VALUE];
        
        StringUtils::StringFormat seed_format;
        if (argsDict[SEED_FORMAT] == "hex")
            seed_format = StringUtils::hex;
        else
            seed_format = StringUtils::ascii;
        
        OptionsDict optionsDict;
        optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = getOptionValue(argsDict[OUTPUT_ENTIRE_CHAIN_OPTION]);
        optionsDict[VERBOSE_OPTION] = getOptionValue(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        outputExtKeysFromSeed(seed, chain, seed_format, optionsDict, traverseType);
    } else if (argsDict[EXTENDEDKEY_VALUE] != "" && argsDict[CHAIN_VALUE] != "") {
        std::string extkey = argsDict[EXTENDEDKEY_VALUE];
        std::string chain = argsDict[CHAIN_VALUE];
        
        OptionsDict optionsDict;
        optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = getOptionValue(argsDict[OUTPUT_ENTIRE_CHAIN_OPTION]);
        optionsDict[VERBOSE_OPTION] = getOptionValue(argsDict[VERBOSE_OPTION]);
        TreeTraversal::Type traverseType = getTreeTraversalOption(argsDict[TREE_TRAVERSAL_OPTION]);
        outputExtKeysFromExtKey(extkey, chain, optionsDict, traverseType);
    } else if (argsDict[EXTENDEDKEY] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        OptionsDict optionsDict;
        optionsDict[OUTPUT_ENTIRE_CHAIN_OPTION] = getOptionValue(argsDict[OUTPUT_ENTIRE_CHAIN_OPTION]);
        optionsDict[VERBOSE_OPTION] = getOptionValue(argsDict[VERBOSE_OPTION]);
        outputKeyAddressofExtKey(extkey, optionsDict);
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
        if (getOptionValue(argsDict[NO_PROMPT])) {
            return handle_arguments(argsDict);
        } else {
            if (noInputEcho) {
                termios oldt;
                tcgetattr(STDIN_FILENO, &oldt);
                termios newt = oldt;
                newt.c_lflag &= ~ECHO;
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            }
            return enter_prompt(argsDict);
        }
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

void visit(const KeyNode& keyNode, const std::string& chainName, const bool isLeafNode,
           const OptionsDict& optionsDict) {
    
    if (! isLeafNode && ! optionsDict.at(OUTPUT_ENTIRE_CHAIN_OPTION))
        return;
    
    outputString("* [Chain " + chainName + "]");
    if (keyNode.isPrivate()) {
        KeyNode keyNodePub= keyNode.getPublic();
        outputString("  * ext pub:  " + toBase58Check(keyNodePub.extkey()));
        outputString("  * ext prv:  " + toBase58Check(keyNode.extkey()));
        if (! optionsDict.at(VERBOSE_OPTION)) {
            outputString("  * priv key: " + keyNode.privkey());
            outputString("  * address:  " + keyNode.address());
        } else {
            outputString("  * uncompressed priv key: " + keyNode.privkey(false));
            outputString("  * uncompressed pub key:  " + uchar_vector(keyNode.pubkeyUncompressed()).getHex());
            outputString("  * uncompressed address:  " + keyNode.address(false));

            outputString("  * compressed priv key: " + keyNode.privkey(true));
            outputString("  * compressed pub key:  " + uchar_vector(keyNode.pubkey()).getHex());
            outputString("  * compressed address:  " + keyNode.address(true));
        }
    } else {
        outputString("  * ext pub:  " + toBase58Check(keyNode.extkey()));
        if (! optionsDict.at(VERBOSE_OPTION)) {
            outputString("  * address:  " + keyNode.address());
        } else {
            //outputString("  * uncompressed pub key:  " + uchar_vector(keyNode.pubkeyUncompressed()).getHex());
            //outputString("  * uncompressed address:  " + keyNode.address(false));
            
            outputString("  * compressed pub key:  " + uchar_vector(keyNode.pubkey()).getHex());
            outputString("  * compressed address:  " + keyNode.address(true));
        }
    }
}

void traverseLevelorder(const KeyNode& keyNode, const TreeChains& treeChains, const std::string& chainName,
                        uint64_t level, std::deque<KeyNode>& keyNodeDeq,
                        std::deque<std::pair<uint64_t,std::string>>& levelNChainDeq,
                        const OptionsDict& optionsDict) {

    bool isLeafNode = false;
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
    } else {
        isLeafNode = true;
    }

    visit(keyNode, chainName, isLeafNode, optionsDict);
    
    if (! keyNodeDeq.empty()) {
        std::pair<uint64_t,std::string> pair = levelNChainDeq.front();
        uint64_t lev = pair.first++;
        std::string cc = pair.second;
        KeyNode node = keyNodeDeq.front();
        keyNodeDeq.pop_front();
        levelNChainDeq.pop_front();
        traverseLevelorder(node, treeChains, cc, lev, keyNodeDeq, levelNChainDeq, optionsDict);
    }
}

void traversePreorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName,
                      const OptionsDict& optionsDict) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        bool isLeafNode = false;
        if (treeChains.empty()) isLeafNode = true;

        if (min == KeyTreeUtil::NODE_IDX_M && max == KeyTreeUtil::NODE_IDX_M) {
            visit(keyNode, KeyTreeUtil::MASTER_NODE_LOWERCASE_M, isLeafNode, optionsDict);
            traversePreorder(keyNode, treeChains, chainName, optionsDict);
        } else {
            for (uint32_t i = min; i <= max; ++i) {
                uint32_t k = i;
                if (isPrivate) k = KeyTreeUtil::toPrime(k);
                std::string childChainName = chainName + "/" + KeyTreeUtil::iToString(k);
                KeyNode childNode = keyNode.getChild(k);
                
                visit(childNode, childChainName, isLeafNode, optionsDict);
                traversePreorder(childNode, treeChains, childChainName, optionsDict);
            }
        }
    }
}

void traversePostorder(const KeyNode& keyNode, TreeChains treeChains, const std::string& chainName,
                       const OptionsDict& optionsDict) {
    if (! treeChains.empty()) {
        IsPrivateNPathRange isPrivateNPathRange = treeChains.front();
        treeChains.pop_front();
        bool isPrivate = isPrivateNPathRange.first;
        Range range = isPrivateNPathRange.second;
        uint32_t min = range.first;
        uint32_t max = range.second;
        bool isLeafNode = false;
        if (treeChains.empty()) isLeafNode = true;

        if (min == KeyTreeUtil::NODE_IDX_M && max == KeyTreeUtil::NODE_IDX_M) {
            traversePostorder(keyNode, treeChains, chainName, optionsDict);
            visit(keyNode, KeyTreeUtil::MASTER_NODE_LOWERCASE_M, isLeafNode, optionsDict);
        } else {
            for (uint32_t i = min; i <= max; ++i) {
                uint32_t k = i;
                if (isPrivate) k = KeyTreeUtil::toPrime(k);
                std::string childChainName = chainName + "/" + KeyTreeUtil::iToString(k);
                KeyNode childNode = keyNode.getChild(k);
                traversePostorder(childNode, treeChains, childChainName, optionsDict);
                visit(childNode, childChainName, isLeafNode, optionsDict);
            }
        }
    }
}

void outputExtKeysFromSeed(const std::string& seed, const std::string& chainStr,
                           StringUtils::StringFormat seedStringFormat, const OptionsDict& optionsDict,
                           TreeTraversal::Type traversalType) {
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
        traversePostorder(prv, treeChains, KeyTreeUtil::MASTER_NODE_LOWERCASE_M, optionsDict);
    else if (traversalType == TreeTraversal::levelorder) {
        treeChains.pop_front();
        std::deque<KeyNode> KeyNodeDeq;
        std::deque<std::pair<uint64_t,std::string>> levelNChainDeq;
        traverseLevelorder(prv, treeChains, KeyTreeUtil::MASTER_NODE_LOWERCASE_M, 0, KeyNodeDeq, levelNChainDeq, optionsDict);
    }
    else
        traversePreorder(prv, treeChains, KeyTreeUtil::MASTER_NODE_LOWERCASE_M, optionsDict);
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
                             const OptionsDict& optionsDict, TreeTraversal::Type traversalType) {
    uchar_vector extendedKey(KeyTreeUtil::extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    TreeChains treeChains = KeyTreeUtil::parseChainString(chainStr, keyNode.isPrivate());
    
    if (optionsDict.at(VERBOSE_OPTION)) outputExtraKeyNodeData(keyNode);

    if (traversalType == TreeTraversal::postorder)
        traversePostorder(keyNode, treeChains, KeyTreeUtil::LEAD_CHAIN_PATH, optionsDict);
    else if (traversalType == TreeTraversal::levelorder) {
        treeChains.pop_front();
        std::deque<KeyNode> KeyNodeDeq;
        std::deque<std::pair<uint64_t,std::string>> levelNChainDeq;
        traverseLevelorder(keyNode, treeChains, KeyTreeUtil::LEAD_CHAIN_PATH, 0, KeyNodeDeq, levelNChainDeq, optionsDict);
    } else
        traversePreorder(keyNode, treeChains, KeyTreeUtil::LEAD_CHAIN_PATH, optionsDict);
}

void outputKeyAddressofExtKey(const std::string& extKey, const OptionsDict& optionsDict) {
    uchar_vector extendedKey(KeyTreeUtil::extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    visit(keyNode, KeyTreeUtil::LEAD_CHAIN_PATH, true, optionsDict);
    if (optionsDict.at(VERBOSE_OPTION)) outputExtraKeyNodeData(keyNode);
    outputString("");
}


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
#include "keynode/keynode.h"
#include "keynode/logger.h"
#include "keynode/CoinClasses/Base58Check.h"

using namespace std;

static const std::string HELP = "help";
static const std::string SEED_FORMAT = "seed_format";

static const std::string SEED = "seed";
static const std::string SEED_HEX = "seed.hex";

static const std::string EXTENDEDKEY = "extkey";
static const std::string CHAIN = "chain";
static const std::string I_MIN = "imin";
static const std::string I_MAX = "imax";

static const std::string SEED_SHORT = "s";
static const std::string SEED_SHORT_HEX_SHORT = "s.h";
static const std::string SEED_HEX_SHORT = "seed.h";
static const std::string SEED_SHORT_HEX = "s.hex";

static const std::string EXTENDEDKEY_SHORT = "ek";
static const std::string CHAIN_SHORT = "c";
static const std::string I_MIN_SHORT = "min";
static const std::string I_MAX_SHORT = "max";

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


void outputExtKeysFromSeed(const std::string seed, const std::string chainStr, StringUtils::StringFormat seedStringFormat);
void outputExtKeysFromExtKey(const std::string extKey, const std::string chainStr);
void outputKeyAddressesFromExtKey(const std::string extKey, uint32_t i_min = 0, uint32_t i_max = 9);
void outputKeyAddressofExtKey(const std::string extKey);
void outputString(const std::string str);
static void setTestNet(bool enabled);
void outputExtKeys(KeyNode& keyNode, std::vector<uint32_t> chain);
static std::vector<uint32_t> parseChainString(const std::string chainStr, bool isPrivate = true);
static std::string iToString(uint32_t i);
uchar_vector extKeyBase58OrHexToBytes(const std::string extKey);
static uchar_vector fromBase58ExtKey(const std::string extKey);
static inline uint32_t toPrime(uint32_t i) { return 0x80000000 | i; }
static inline bool isPrime(uint32_t i) { return 0x80000000 & i; }


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
        } else {
            throw std::invalid_argument("Invalid arguments.");
        }
        //Logger::debug("arg: " + arg);
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
        
        outputExtKeysFromSeed(seed, chain, seed_format);
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[CHAIN] != "") {

        std::string extkey = argsDict[EXTENDEDKEY];
        std::string chain = argsDict[CHAIN];
        outputExtKeysFromExtKey(extkey, chain);
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
    //setTestNet(true);

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



void outputString(const std::string str) {
    Logger::log(str);
}

uchar_vector extKeyBase58OrHexToBytes(const std::string extKey) {
    uchar_vector extendedKey;
    if (isBase58CheckValid(extKey))
        extendedKey = fromBase58ExtKey(extKey);
    else if (StringUtils::isHex(extKey))
        extendedKey = uchar_vector(extKey);
    else
        throw std::runtime_error("Invalid extended key. Extended key must be in base58 or hex form.");
    
    return extendedKey;
}

void outputExtKeys(KeyNode& keyNode, std::vector<uint32_t> chain) {
    stringstream chainname;
    chainname << "m";
    for(auto it=chain.begin(); it!=chain.end(); ++it) {
        uint32_t k = *it;
        chainname << "/" << iToString(k);
        outputString("* [Chain " + chainname.str() + "]");
        
        keyNode = keyNode.getChild(k);
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
}

void outputExtKeysFromSeed(const std::string seed, const std::string chainStr, StringUtils::StringFormat seedStringFormat) {
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
    std::vector<uint32_t> chain = parseChainString(chainStr, prv.isPrivate());
    outputExtKeys(prv, chain);
}

void outputExtKeysFromExtKey(const std::string extKey, const std::string chainStr) {
    uchar_vector extendedKey(extKeyBase58OrHexToBytes(extKey));
    KeyNode keyNode(extendedKey);
    std::vector<uint32_t> chain = parseChainString(chainStr, keyNode.isPrivate());
    outputExtKeys(keyNode, chain);
}

void outputKeyAddressesFromExtKey(const std::string extKey, uint32_t i_min, uint32_t i_max) {
    uchar_vector extendedKey(extKeyBase58OrHexToBytes(extKey));
    
    KeyNode keyNode(extendedKey);
    for (uint32_t i = i_min; i < i_max; i++ ) {
        KeyNode child = keyNode.getChild(i);
        if (child.isPrivate()) outputString("  * priv key: " + child.privkey());
        outputString("  * address: " + child.address());
        outputString("");
    }
}

void outputKeyAddressofExtKey(const std::string extKey) {
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


uchar_vector fromBase58ExtKey(const std::string extKey) {
    static unsigned int dummy = 0;
    uchar_vector fillKey;
    fromBase58Check(extKey, fillKey, dummy);
    static const std::string VERSION_BYTE("04");
    return uchar_vector(VERSION_BYTE+fillKey.getHex()); //append VERSION_BYTE to begining
}

std::vector<uint32_t> parseChainString(const std::string chainStr, bool isPrivate) {
    std::vector<uint32_t> chain;
    
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
            uint32_t num = std::stoi(node);
            chain.push_back(toPrime(num));
        } else {
            uint32_t num = std::stoi(node);
            chain.push_back(num);
        }
    }
    
    return chain;
}

void setTestNet(bool enabled) {
    if (enabled) Coin::HDKeychain::setVersions(0x04358394, 0x043587CF);
    else Coin::HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
}

std::string iToString(uint32_t i) {
    std::stringstream ss;
    ss << (0x7fffffff & i);
    if (isPrime(i)) { ss << "'"; }
    return ss.str();
}


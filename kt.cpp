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
#include "keytree.h"
#include "logger.h"
using namespace std;

static bool IS_DEBUG = false;
static const std::string HELP = "help";

static const std::string SEED = "seed";
static const std::string EXTENDEDKEY = "extkey";
static const std::string CHAIN = "chain";
static const std::string I_MIN = "imin";
static const std::string I_MAX = "imax";
static const std::string SEED_SHORT = "s";
static const std::string EXTENDEDKEY_SHORT = "ek";
static const std::string CHAIN_SHORT = "c";
static const std::string I_MIN_SHORT = "min";
static const std::string I_MAX_SHORT = "max";

static const std::string appName = "./kt";
static const std::string exampleArg1 = " -seed 000102030405060708090a0b0c0d0e0f -chain \"m/0'/0\"";
static const std::string exampleArg2 = " -s 000102030405060708090a0b0c0d0e0f -c \"m/0'/0\"";
static const std::string exampleArg3 = " -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -imin 0 -imax 3";
static const std::string exampleArg4 = " -extkey \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" -min 0 -max 3";

static const std::string exampleArg5 = " -extkey \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\"";
static const std::string exampleArg6 = " -ek \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\"";
static const std::string exampleArg7 = " -ek \"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7\" -c \"m/0'/0\"";
static const std::string exampleArg8 = " -extkey \"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw\" -chain \"m/0/0\"";

/*
 test arguments
 -seed 000102030405060708090a0b0c0d0e0f -chain "m/0'/0"
 -s 000102030405060708090a0b0c0d0e0f -c "m/0'/0"
 -extkey "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" -imin 0 -imax 3
 -extkey "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw" -min 0 -max 3
 -extkey "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
 -extkey "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
 -ek "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" -c "m/0'/0"
 -ek "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw" -c "m/0/0"
 //*/


void printExtKeys(KeyTree& keyTree) {
    while (! keyTree.isAtEndOfChain()) { //TODO: change to iterator instead
        KeyNode data = keyTree.getNextInChain();
        Logger::log("* [Chain " + data.chain + "]");
        Logger::log("  * ext pub: " + data.extpub);
        if (data.extprv != "") Logger::log("  * ext prv: " + data.extprv);
        //Logger::log("  * priv key: " + data.privkey);
        //Logger::log("  * address: " + data.address);
        //Logger::log("");
    }
}

void printExtKeysFromSeed(const std::string seed, const std::string chainStr) {
    KeyTree keyTree(seed, chainStr);
    KeyNode data = keyTree.getCurrentInChain();
    Logger::debug("Master (hex): " + seed);
    Logger::log("* [Chain " + data.chain + "]");
    Logger::log("  * ext pub: " + data.extpub);
    Logger::log("  * ext prv: " + data.extprv);
    //Logger::log("  * priv key: " + data.privkey);
    //Logger::log("  * address: " + data.address);
    //Logger::log("");
    printExtKeys(keyTree);
}

void printExtKeysFromExtKey(const std::string extKey, const std::string chainStr) {
    KeyTree keyTree(extKey, chainStr, 0, 9);
    printExtKeys(keyTree);
}

void printKeyAddressesFromExtKey(const std::string extKey, uint32_t i_min = 0, uint32_t i_max = 9) {
    for (uint32_t i = i_min; i < i_max; i++ ) {
        KeyNode data = KeyTree::getChildOfExtKey(extKey, i);
        //Logger::log("* [Chain " + data.chain + "]");
        //Logger::log("  * ext pub: " + data.extpub);
        //Logger::log("  * ext prv: " + data.extprv);
        if (data.privkey != "") Logger::log("  * priv key: " + data.privkey);
        Logger::log("  * address: " + data.address);
        Logger::log("");
    }
}

void printKeyAddressofExtKey(const std::string extKey) {
    KeyTree keyTree(extKey, "m", 0, 0);
    KeyNode data = keyTree.getCurrentInChain();
    //Logger::log("* [Chain " + data.chain + "]");
    Logger::log("  * ext pub: " + data.extpub);
    if (data.extprv != "") Logger::log("  * ext prv: " + data.extprv);
    if (data.privkey != "") Logger::log("  * priv key: " + data.privkey);
    Logger::log("  * address: " + data.address);
    Logger::log("");
}


void testVector1() {
    printExtKeysFromSeed("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000");
}

void testVector2() {
    std::string seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    printExtKeysFromSeed(seed, "m/0/2147483647'/1/2147483646'/2");
}

void testPrintExtKeysFromSeed() {
    printExtKeysFromSeed("000102030405060708090a0b0c0d0e0f", "m/0'/0");
}

void testPrintExtKeysFromExtKey() {
    //printExtKeysFromExtKey("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", "m/0'/0"); //priv
    //printExtKeysFromExtKey("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", "m/0'/0"); //pub  - cant do chain with ' on ext pubkey will throw except, do below
    //printExtKeysFromExtKey("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", "m/0/0"); //pub
    
    //printExtKeysFromExtKey("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "m/0'/0"); //priv
    printExtKeysFromExtKey("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "m/0'/0"); //pub  - cant do chain with ' on ext pubkey will throw except, do below
    //printExtKeysFromExtKey("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "m/0/0"); //pub
}

void testPrintKeyAddressesFromExtKey() {
    //printKeyAddressesFromExtKey("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", 0, 2); //priv
    //printKeyAddressesFromExtKey("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", 0, 2); //pub
    
    printKeyAddressesFromExtKey("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", 0, 2); //priv
    //printKeyAddressesFromExtKey("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", 0, 2); //pub
}

void testPrintKeyAddressofExtKey() {
    //printKeyAddressofExtKey("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"); //priv
    //printKeyAddressofExtKey("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"); //pub
    
    printKeyAddressofExtKey("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"); //priv
    printKeyAddressofExtKey("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"); //pub
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
        }
        else if (arg == SEED || arg == SEED_SHORT) {
            ++it;
            argsDict[SEED] = *it;
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

void printExamples() {
    Logger::log("Input parameters can be in hex or base58.");
    Logger::log("Here are some examples:");
    Logger::log("");
    
    Logger::log("Given Seed and Chain will print Child Extended Keys:");
    Logger::log(appName+exampleArg1);
    Logger::log(appName+exampleArg2);
    Logger::log("");
    
    Logger::log("Given Extended Key and Chain will print Child Extended Keys:");
    Logger::log(appName+exampleArg7);
    Logger::log(appName+exampleArg8);
    Logger::log("");
    
    Logger::log("Given Extended Key and range will print Private Keys and Addresses from child of Extended Key in given range:");
    Logger::log(appName+exampleArg3);
    Logger::log(appName+exampleArg4);
    Logger::log("");
    
    Logger::log("Given Extended Key will print Private Key and Address of Extended Key:");
    Logger::log(appName+exampleArg5);
    Logger::log(appName+exampleArg6);
    Logger::log("");
}

int handle_arguments(std::map<std::string, std::string> argsDict) {
    Logger::debug("Arguments:");
    for (auto it = argsDict.begin(); it != argsDict.end(); ++it) {
        Logger::debug("\tkey: " + it->first + " value: " + it->second);
    }
    Logger::debug("");
    if (argsDict[HELP] == HELP) {
        printExamples();
        return 0;
    } else if (argsDict[SEED] != "" && argsDict[CHAIN] != "") {
        std::string seed = argsDict[SEED];
        std::string chain = argsDict[CHAIN];
        printExtKeysFromSeed(seed, chain);
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[CHAIN] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        std::string chain = argsDict[CHAIN];
        printExtKeysFromExtKey(extkey, chain);
    } else if (argsDict[EXTENDEDKEY] != "" && argsDict[I_MIN] != "" && argsDict[I_MAX] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        uint32_t i_min = std::stoi(argsDict[I_MIN]);
        uint32_t i_max = std::stoi(argsDict[I_MAX]);
        printKeyAddressesFromExtKey(extkey, i_min, i_max);
    } else if (argsDict[EXTENDEDKEY] != "") {
        std::string extkey = argsDict[EXTENDEDKEY];
        printKeyAddressofExtKey(extkey);
    } else {
        throw std::invalid_argument("Invalid arguments.");
    }
    
    return 0;
}



int main(int argc, const char * argv[]) {
    Logger::setLogLevelError();
    //Logger::setLogLevelWarning();
    //Logger::setLogLevelDebug();
    //Logger::setLogLevelInfo();
    
    KeyTree::setTestNet(true);
    KeyTree::setTestNet(false);
    
    if (IS_DEBUG) {
        //testVector1();
        //testVector2();
        
        //testPrintExtKeysFromSeed();
        //testPrintExtKeysFromExtKey();
        //testPrintKeyAddressesFromExtKey();
        testPrintKeyAddressofExtKey();
    }
    
    try {
        std::map<std::string, std::string> argsDict = parse_arguments(argv+1, argv+argc);
        return handle_arguments(argsDict);
    }
    catch (const std::invalid_argument& err) {
        Logger::log("Error: " + std::string(err.what()));
        Logger::log("---------------------------------------------------");
        printExamples();
    }
    catch (const std::runtime_error& err) {
        Logger::log("Error: " + std::string(err.what()));
    }
}


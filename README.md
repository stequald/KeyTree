KeyTree
===========

KeyTree is a Bitcoin HDWallet command line tool. To build simply type Make in the directory.


Motivation
===========

Excerpt from [https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki]

The Bitcoin reference client uses randomly generated keys. In order to avoid the necessity for a backup after every transaction, (by default) 100 keys are cached in a pool of reserve keys. Still, these wallets are not intended to be shared and used on several systems simultaneously. They support hiding their private keys by using the wallet encrypt feature and not sharing the password, but such "neutered" wallets lose the power to generate public keys as well.

Deterministic wallets do not require such frequent backups, and elliptic curve mathematics permit schemes where one can calculate the public keys without revealing the private keys. This permits for example a webshop business to let its webserver generate fresh addresses (public key hashes) for each order or for each customer, without giving the webserver access to the corresponding private keys (which are required for spending the received funds).

However, deterministic wallets typically consist of a single "chain" of keypairs. The fact that there is only one chain means that sharing a wallet happens on an all-or-nothing basis. However, in some cases one only wants some (public) keys to be shared and recoverable. In the example of a webshop, the webserver does not need access to all public keys of the merchant's wallet; only to those addresses which are used to receive customer's payments, and not for example the change addresses that are generated when the merchant spends money. Hierarchical deterministic wallets allow such selective sharing by supporting multiple keypair chains, derived from a single root.

[https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki]:https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

Purpose
===========
KeyTree is meant to be a program that lets users have the full flexibility and features of HDWallets available to them at their fingertips. KeyTree is meant to do one thing and do it well. It is meant to be a small program with minimal amount of code such that it is easily audible. The only dependency is OpenSSL. Thus it is easy to build and run on a freshly installed offline operating system, since OpenSSL usually comes pre-install in most popular Unix-like operating systems.

Though KeyTree  is an implementation of HDWallets, it is not to be confused with services like [BlockChain’s My Wallet](https://blockchain.info/wallet) or [Armory](https://bitcoinarmory.com/). KeyTree is a bitcoin key generater and manager. KeyTree does not generate transactions or send them. It is  meant to be used on an airgap, offline computer to generate keys.

There are other tools that have HDWallet implementations, but their purposes are different. For example, [sx](https://github.com/spesmilo/sx) is more of a general purpose Bitcoin command-line tool for power users and [Electrum](https://github.com/spesmilo/electrum) uses it to enumerate accounts derived from a seed with the scheme m/0’/n/.


#### How to use:

Extended Keys can be in hex or base58. Seed can be in ASCII or hex. Examples below.

###### Given seed and chain KeyTree will print child extended keys, bitcoin private keys and addresses:
    ./kt --seed "correct horse battery staple" --chain "m/0'/0"
    ./kt --seed.hex 000102030405060708090a0b0c0d0e0f --chain "m/0'/0"

###### Given extended key and chain KeyTree will print child extended keys, bitcoin private keys and addresses:
    ./kt --extkey xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7 --chain "m/0'/0"
    ./kt --extkey xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw --chain "m/0/0"

###### Given extended key KeyTree will print extended keys, private key and address of extended key:
    ./kt --extkey xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
    ./kt --extkey xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw

###### It is also possible to print multiple chain paths together:
    ./kt --seed.hex "000102030405060708090a0b0c0d0e0f" --chain "m/0'/(3-6)'/(1-2)/8"
    ./kt --extkey "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" --chain "m/0'/(5-8)'"

###### It is also possible to output the nodes in a different order:
    ./kt --seed "correct horse battery staple" --chain "m/0/(3-4)/(1-2)" --traverse levelorder
    ./kt --seed.hex "000102030405060708090a0b0c0d0e0f" --chain "m/0'/(3-4)'/6'" -trav postorder

###### For more info on nodes use the verbose option:
    ./kt --verbose -s.h "000102030405060708090a0b0c0d0e0f" --chain "m/0'/(3-4)'/6'"
    ./kt -v -ek "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

##### For more on how to use KeyTree do:
    $./kt --help
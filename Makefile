CXX = g++
CXXFLAGS = -std=c++0x -Wall -g

COINCLASSESSRCDIR = ./keytree/CoinClasses
KEYTREESRCDIR = ./keytree


HEADERS = \
    $(COINCLASSESSRCDIR)/hdkeys.h \
    $(COINCLASSESSRCDIR)/hash.h \
    $(COINCLASSESSRCDIR)/secp256k1.h \
    $(COINCLASSESSRCDIR)/BigInt.h \
    $(COINCLASSESSRCDIR)/uchar_vector.h


kt: kt.cpp keytree.o logger.o hdkeys.o
	$(CXX) $(CXXFLAGS) -o $@ $< keytree.o logger.o hdkeys.o -lcrypto

keytree.o: $(KEYTREESRCDIR)/keytree.cpp $(COINCLASSESSRCDIR)/Base58Check.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

logger.o: $(KEYTREESRCDIR)/logger.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

hdkeys.o: $(COINCLASSESSRCDIR)/hdkeys.cpp $(HEADERS) 
	$(CXX) $(CXXFLAGS) -o $@ -c $<

clean:
	-rm -rf *.o kt

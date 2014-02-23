CXX = g++
CXXFLAGS = -std=c++0x -Wall -g

COINCLASSESSRCDIR = ./keynode/CoinClasses
KEYNODESRCDIR = ./keynode


HEADERS = \
    $(COINCLASSESSRCDIR)/hdkeys.h \
    $(COINCLASSESSRCDIR)/hash.h \
    $(COINCLASSESSRCDIR)/secp256k1.h \
    $(COINCLASSESSRCDIR)/BigInt.h \
    $(COINCLASSESSRCDIR)/uchar_vector.h


kt: keytree.cpp keynode.o logger.o hdkeys.o keytreeutil.o typedefs.h
	$(CXX) $(CXXFLAGS) -o $@ $< keynode.o logger.o hdkeys.o keytreeutil.o -lcrypto

keytreeutil.o: keytreeutil.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

keynode.o: $(KEYNODESRCDIR)/keynode.cpp $(COINCLASSESSRCDIR)/Base58Check.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

logger.o: $(KEYNODESRCDIR)/logger.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

hdkeys.o: $(COINCLASSESSRCDIR)/hdkeys.cpp $(HEADERS) 
	$(CXX) $(CXXFLAGS) -o $@ -c $<

clean:
	-rm -rf *.o $(KEYNODESRCDIR)/*.o $(COINCLASSESSRCDIR)/*.o *~ $(KEYNODESRCDIR)/*~ $(COINCLASSESSRCDIR)/*.o~ kt.dSYM kt

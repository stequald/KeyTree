EXECUTABLE = kt
CC = g++
CFLAGS = -std=c++0x -Wall -g 
COMPILE = $(CC) $(CFLAGS) -c
OBJFILES := $(patsubst %.cpp,%.o,$(wildcard *.cpp))

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJFILES)
	$(CC) -o $(EXECUTABLE) $(OBJFILES) -lcrypto


%.o: %.cpp *.h
	$(COMPILE) -o $@ $< 

clean:
	rm -f $(OBJFILES) $(EXECUTABLE)

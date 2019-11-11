CC = g++
CFLAGS = -std=c++14 -Wall -Wextra -pedantic -lm -g -pthread
SOURCES = dns.cpp
PROGRAM = dns
LOGIN = xzales13
FILES = Makefile README manual.pdf dns.cpp

all: dns

dns: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(PROGRAM)

run: all
	./dns -r -s 8.8.8.8 www.seznam.cz

test: all
	echo "TBD"

clean:
	rm -f $(PROGRAM) $(LOGIN).tar

tar:
	tar -cf $(LOGIN).tar $(FILES)

push: clean
	rsync -avuzz -e ssh -v /mnt/e/Škola/ISA/project/ eva:~/isa

mem: all
	valgrind ./dns -r -x -6 -s kazi.fit.vutbr.cz -p 1234 www.fit.vut.cz


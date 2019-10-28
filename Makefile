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
	./dns -r -x -s kazi.fit.vutbr.cz www.fit.vut.cz

test: all
	echo "TBD"

clean:
	rm -f $(PROGRAM) $(LOGIN).tar

tar:
	tar -cf $(LOGIN).tar $(FILES)

push: clean
	rsync -avuz -e ssh /mnt/e/Škola/ISA/project/ merlin:~/isa

mem: all
	valgrind ./dns -r -x -6 -s kazi.fit.vutbr.cz -p 1234 www.fit.vut.cz


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
	./dns -r -s kazi.fit.vutbr.cz www.ietf.org

test: all
	@echo -e "\033[0;32mTEST 1\033[0m"
	./dns -r -s kazi.fit.vutbr.cz www.fit.vut.cz
	@echo
	@echo -e "\033[0;32mTEST 2\033[0m"
	./dns -r -s kazi.fit.vutbr.cz www.ietf.org
	@echo
	@echo -e "\033[0;32mTEST 3\033[0m"
	./dns -s kazi.fit.vutbr.cz www.fit.vut.cz
	@echo
	@echo -e "\033[0;32mTEST 4\033[0m"
	./dns -s kazi.fit.vutbr.cz www.ietf.org
	@echo
	@echo -e "\033[0;32mTEST 5\033[0m"
	./dns -r -s 8.8.8.8 www.seznam.cz
	@echo
	@echo -e "\033[0;32mTEST 6\033[0m"
	./dns -r -6 -s 8.8.8.8 www.seznam.cz
	@echo
	@echo -e "\033[0;32mTEST 7\033[0m"
	./dns -r -x -s kazi.fit.vutbr.cz 8.8.8.8
	@echo
	@echo -e "\033[0;32mTEST 8\033[0m"
	./dns -r -x -s kazi.fit.vutbr.cz 2001:4860:4860::8888
	@echo
	@echo -e "\033[0;32mTEST 9\033[0m"
	./dns -x -s kazi.fit.vutbr.cz 2001:4860:4860::8888
	@echo
	@echo -e "\033[0;32mTEST 10\033[0m"
	./dns -x -s kazi.fit.vutbr.cz 8.8.4.4
	@echo


clean:
	rm -f $(PROGRAM) $(LOGIN).tar

tar:
	tar -cf $(LOGIN).tar $(FILES)

push: clean
	rsync -avuzz -e ssh -v /mnt/e/Škola/ISA/project/ eva:~/isa

mem: all
	valgrind ./dns -r -x -6 -s kazi.fit.vutbr.cz -p 1234 www.fit.vut.cz


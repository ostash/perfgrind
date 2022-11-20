-include site.mak

PROGRAMS = pgcollect pginfo pgconvert
SOURCES = AddressResolver.cpp Profile.cpp
HEADERS = AddressResolver.h Profile.h

PREFIX = /usr/local

KCACHEGRIND = kcachegrind

CFLAGS = -Wall -Wextra -g
PGCOLLECT_FLAGS = -F 2048 -s

all: $(PROGRAMS) 

pgcollect: pgcollect.c
	$(CC) -std=gnu99  -O2 $(CFLAGS) ${FLAGS} -D_GNU_SOURCE -o pgcollect  pgcollect.c

pgconvert: pgconvert.cpp $(SOURCES) $(HEADERS)
	$(CXX) -std=c++03 -O2 $(CFLAGS) ${FLAGS} -o pgconvert  pgconvert.cpp $(SOURCES) -ldw -lelf

pginfo: pginfo.cpp $(SOURCES) $(HEADERS)
	$(CXX) -std=c++03 -O2 $(CFLAGS) ${FLAGS} -o pginfo     pginfo.cpp    $(SOURCES) -ldw -lelf

# only used to be traced itself
pginfo_dbg: pginfo.cpp $(SOURCES) $(HEADERS)
	$(CXX) -std=c++03 -O  $(CFLAGS) ${FLAGS} -g -fno-omit-frame-pointer -o pginfo_dbg pginfo.cpp    $(SOURCES) -ldw -lelf


.PHONY: install uninstall clean clean-dev clean-check


install:
	install $(PROGRAMS) $(PREFIX)/bin

uninstall:
	cd $(PREFIX)/bin && rm $(PROGRAMS) 


clean: clean-dev clean-check
	rm -rf pgcollect pginfo pginfo_dbg pgconvert

clean-dev:
	rm -rf *.o

clean-check:
	rm -rf *.pgdata *.grind

check_ls.grind check.grind:
	@echo "run \"$(MAKE) check\" first" && exit 1

check:	pgcollect pgconvert pginfo pginfo_dbg
	@echo ""; echo "collecting some data of ls binary (likely without full symbols)..."
	./pgcollect check_ls.pgdata $(PGCOLLECT_FLAGS) -- ls -l /usr/bin  1>/dev/null
	@echo ""; echo "collecting data of checking that (guaranteed to have symbols for binary pginfo_dbg) ..."
	./pgcollect check.pgdata    $(PGCOLLECT_FLAGS) -- ./pginfo_dbg callgraph check_ls.pgdata
	@echo ""; echo "checking its infos ..."
	./pginfo callgraph check.pgdata
	@echo ""; echo "converting both collections to callgrind format ..."
	./pgconvert check_ls.pgdata -d object       1> check_ls.grind  # old: stdout
	./pgconvert check.pgdata    -d source -i       check.grind     # new: second option
	@echo ""; echo "done, you may want to issue \"make open-checkfiles\" to open the result via kcachegrind"

open-checkfiles:	check_ls.grind check.grind
	$(KCACHEGRIND) ./check_ls.grind &
	$(KCACHEGRIND) ./check.grind &

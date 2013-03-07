all: pgcollect

pgcollect: pgcollect.c
	gcc -std=gnu99 -Wall -g -D_GNU_SOURCE -o pgcollect pgcollect.c

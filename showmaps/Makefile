VERSION     = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

PROGS       = showmaps

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: $(PROGS)

showmaps: showmaps.c $(COMM_HDR)
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) *.o *~ a.out core core.[1-9][0-9]* *.stackdump
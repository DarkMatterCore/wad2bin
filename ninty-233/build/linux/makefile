MAJOR      = 1
MINOR      = 0
PATCH      = 0
VERSION    = .$(MAJOR).$(MINOR).$(PATCH)

STATIC_LIB = libninty-233.a
SHARED_LIB = libninty-233.so

OUTDIR     = ../../bin/linux/
ST_OBJDIR  = $(OUTDIR)static_obj/
SH_OBJDIR  = $(OUTDIR)shared_obj/
SRCDIR     = ../../src/

CC         = gcc
CFLAGS     = -std=c99 -Wall -Wextra -pedantic
SONAME     = $(SHARED_LIB).$(MAJOR)
SH_OBJ     = $(SH_OBJDIR)ninty-233.o $(SH_OBJDIR)ecc.o $(SH_OBJDIR)sha1.o $(SH_OBJDIR)mini-gmp.o
ST_OBJ     = $(ST_OBJDIR)ninty-233.o $(ST_OBJDIR)ecc.o $(ST_OBJDIR)sha1.o $(ST_OBJDIR)mini-gmp.o

.PHONY: all
all: $(STATIC_LIB) $(SHARED_LIB)

.PHONY: static
static: $(STATIC_LIB)

.PHONY: shared
shared: $(SHARED_LIB)

$(STATIC_LIB): $(ST_OBJ)
	@ar rcs $(OUTDIR)$(STATIC_LIB) $^

$(SHARED_LIB): $(SH_OBJ)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $(OUTDIR)$(SHARED_LIB)$(VERSION) $^

$(SH_OBJDIR)%.o:
	@mkdir -p $(SH_OBJDIR)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<
$(SH_OBJDIR)ninty-233.o: $(SRCDIR)ninty-233.c $(SRCDIR)ninty-233.h $(SRCDIR)ecc/ecc.h $(SRCDIR)sha1/sha1.h $(SRCDIR)mini-gmp/mini-gmp.h
$(SH_OBJDIR)ecc.o:       $(SRCDIR)ecc/ecc.c $(SRCDIR)ecc/ecc.h
$(SH_OBJDIR)sha1.o:      $(SRCDIR)sha1/sha1.c $(SRCDIR)sha1/sha1.h
$(SH_OBJDIR)mini-gmp.o:  $(SRCDIR)mini-gmp/mini-gmp.c $(SRCDIR)mini-gmp/mini-gmp.h

$(ST_OBJDIR)%.o:
	@mkdir -p $(ST_OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<
$(ST_OBJDIR)ninty-233.o: $(SRCDIR)ninty-233.c $(SRCDIR)ninty-233.h $(SRCDIR)ecc/ecc.h $(SRCDIR)sha1/sha1.h $(SRCDIR)mini-gmp/mini-gmp.h
$(ST_OBJDIR)ecc.o:       $(SRCDIR)ecc/ecc.c $(SRCDIR)ecc/ecc.h
$(ST_OBJDIR)sha1.o:      $(SRCDIR)sha1/sha1.c $(SRCDIR)sha1/sha1.h
$(ST_OBJDIR)mini-gmp.o:  $(SRCDIR)mini-gmp/mini-gmp.c $(SRCDIR)mini-gmp/mini-gmp.h

.PHONY: clean
clean:
	rm -f $(OUTDIR)$(STATIC_LIB) $(OUTDIR)$(SHARED_LIB) $(OUTDIR)$(SHARED_LIB)$(VERSION) $(ST_OBJDIR)*.o $(SH_OBJDIR)*.o


# $Id: Makefile,v 1.3 2007/10/03 06:58:25 schmolli Exp $

CC = gcc

# if you are not using gmake, you may need to convert the ":=" variables into
# "=" variables.  you cannot have recursive definitions if you do that.
CFLAGS   := -fPIC -O2 -Wall -Werror -pedantic $(CFLAGS)
CPPFLAGS := -I.

OUT        = pam_chroot.so
INSTALLDIR = /lib/security
TEST       = pam_chroot_test

all:	$(OUT)

%.so: %.o
	$(LD) -x --shared -o $@ $< -lpam

test: $(TEST)
	@echo Running system tests to verify basic functionality.
	./$(TEST) -s
	@echo Running all tests.
	./$(TEST) -a

$(TEST): $(TEST).o $(OUT)
	$(CC) -o $@ $< -lpam $(PWD)/pam_chroot.so

clean:
	rm -f *.o $(OUT) $(TEST)

install:
	install -s -o0 -g0 -m755 $(OUT) $(INSTALLDIR)

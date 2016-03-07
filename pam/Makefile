##
## Copyright (c) 2016 Christian Pointner <equinox@spreadspace.org>
##               2016 Markus Grüneis <gimpf@gimpf.org>
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## * Redistributions of source code must retain the above copyright notice, this
##   list of conditions and the following disclaimer.
##
## * Redistributions in binary form must reproduce the above copyright notice,
##   this list of conditions and the following disclaimer in the documentation
##   and/or other materials provided with the distribution.
##
## * Neither the name of whawty.auth nor the names of its
##   contributors may be used to endorse or promote products derived from
##   this software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##

CFLAGS := -Wall -Wextra -fPIC
LDFLAGS := -lpam

PAMLIB := pam_whawty.so

C_OBJS := pam_whawty.o

C_SRCS := $(C_OBJS:%.o=%.c)

.PHONY: clean distclean

all: $(PAMLIB)

%.d: %.c
	@set -e; rm -f $@; \
  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
  sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
  rm -f $@.$$$$; echo '(re)building $@'

ifneq ($(MAKECMDGOALS),distclean)
-include $(C_SRCS:%.c=%.d)
endif

$(PAMLIB): $(C_OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $(C_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

strip: $(PAMLIB)
	strip $<

distclean: clean
	find . -name *.o -exec rm -f {} \;
	find . -name "*.\~*" -exec rm -rf {} \;
	rm -f pam_whawty.8

clean:
	rm -f *.o
	rm -f *.d
	rm -f *.d.*
	rm -f $(PAMLIB)

manpage: pam_whawty.8

pam_whawty.8: pam_whawty.8.txt
	a2x -f manpage $<
	@ sed -i -e 's/^  \[ \([^ ]*\)/  [ \\fB\1\\fR/' $@

##
## Copyright (c) 2016-2019 whawty contributors (see AUTHORS file)
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

GOCMD := go
ifdef GOROOT
GOCMD = $(GOROOT)/bin/go
endif

EXECUTEABLE := whawty-auth

all: build
.PHONY: vet format ui build clean distclean

vet:
	$(GOCMD) vet ./...

format:
	$(GOCMD) fmt ./...

ui:
	$(GOCMD) generate ./ui

build: ui
	$(GOCMD) build -o $(EXECUTEABLE) ./cmd/whawty-auth

dev:
	$(GOCMD) build -o $(EXECUTEABLE) -tags=dev ./cmd/whawty-auth

clean:
	rm -f $(EXECUTEABLE)

distclean: clean
	rm -f ui/assets_vfsdata.go
	rm -f doc/man/$(EXECUTEABLE).8

manpage: doc/man/$(EXECUTEABLE).8

doc/man/$(EXECUTEABLE).8: doc/man/$(EXECUTEABLE).8.txt
	a2x -f manpage $<

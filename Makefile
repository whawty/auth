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
.PHONY: format vet cover serve-cover clean distclean ui-icons

format:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

test: vet
	$(GOCMD) test `$(GOCMD) list ./... | grep -v 'sasl/examples'`

test-verbose: vet
	$(GOCMD) test -v `$(GOCMD) list ./... | grep -v 'sasl/examples'`

cover:
	mkdir -p ./.coverage
	$(GOCMD) test -v `$(GOCMD) list ./... | grep -v 'sasl/examples'` -covermode=count -coverprofile=./.coverage/profile
	$(GOCMD) tool cover -html=./.coverage/profile -o ./.coverage/index.html

serve-cover:
	cd ./.coverage; python3 -m http.server

build: test
	$(GOCMD) build -o $(EXECUTEABLE) ./cmd/whawty-auth

dev: test
	$(GOCMD) build -o $(EXECUTEABLE) -tags=dev ./cmd/whawty-auth

clean:
	rm -f $(EXECUTEABLE)

distclean: clean
	rm -f doc/man/$(EXECUTEABLE).8

# Icons of the web interface. `make ui-icons` downloads the lucide-static npm
# package and regenerates the sprite and its license from it. Without internet
# access, pass the directory of an unpacked package: make ui-icons LUCIDE=<dir>
UI_ICONS := check circle-alert key-round lock-keyhole log-in log-out search shield shield-off trash-2 user-plus x
LUCIDE_VERSION := 1.59.0
LUCIDE_SHA256 := 39e2f835692c193233ac7bcdf34eb0cc2da0f839fd9f3674c34d2751bccf37f0
LUCIDE_URL := https://registry.npmjs.org/lucide-static/-/lucide-static-$(LUCIDE_VERSION).tgz
UI_ICONS_DIR := ui/assets/vendor/lucide

ui-icons:
ifdef LUCIDE
	$(GOCMD) run ui/tools/iconsprite.go -src $(LUCIDE) -out $(UI_ICONS_DIR)/icons.svg $(UI_ICONS)
	cp $(LUCIDE)/LICENSE $(UI_ICONS_DIR)/LICENSE
else
	tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	curl -fsSL -o "$$tmp/lucide.tgz" $(LUCIDE_URL) && \
	echo "$(LUCIDE_SHA256)  $$tmp/lucide.tgz" | sha256sum -c --quiet && \
	tar -xzf "$$tmp/lucide.tgz" -C "$$tmp" package/package.json package/LICENSE package/icons && \
	$(MAKE) --no-print-directory ui-icons LUCIDE="$$tmp/package"
endif

manpage: doc/man/$(EXECUTEABLE).8

doc/man/$(EXECUTEABLE).8: doc/man/$(EXECUTEABLE).8.txt
	a2x -f manpage $<

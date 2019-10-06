# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


DEPTH		= ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules/cryptoAPI

MODFILES = \
	gnupg.js \
	gnupg-decryption.jsm \
	gnupg-keylist.jsm \
	gnupg-key.jsm \
	openpgp-js.js \
	interface.js

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

build: $(GENFILES)

all: build

clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules/cryptoAPI $(MODFILES)

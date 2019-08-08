# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules

MODFILES =  \
	subprocess.jsm \
	enigmailprocess_shared_unix.js \
	enigmailprocess_worker_common.js \
	enigmailprocess_common.jsm \
	enigmailprocess_shared_win.js \
	enigmailprocess_worker_unix.js \
	enigmailprocess_main.jsm \
	enigmailprocess_unix.jsm \
	enigmailprocess_worker_win.js \
	enigmailprocess_shared.js \
	enigmailprocess_win.jsm

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@


all: $(GENFILES)

clean: $(MODFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules $^

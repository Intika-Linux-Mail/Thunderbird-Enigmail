# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules

MODFILES =  \
	subprocess.jsm \
	enigmailprocess_common.jsm \
	enigmailprocess_main.jsm \
	enigmailprocess_unix.jsm \
	enigmailprocess_win.jsm

WORKERS = \
	enigmailprocess_shared.js \
	enigmailprocess_shared_unix.js \
	enigmailprocess_shared_win.js \
	enigmailprocess_worker_common.js \
	enigmailprocess_worker_unix.js \
	enigmailprocess_worker_win.js

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@


all: $(GENFILES) deploy

deploy:
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/modules $(WORKERS)


clean: $(MODFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules $^

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/jsunit

MODFILES = \
           Assert.jsm \
           jsunit-exec.js \
           jsunit-main.jsm \
           jsunit-service.js \
           jsunit-wrapper.js 


GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

all: dirs build

build: $(GENFILES)


clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/jsunit $(MODFILES)

.PHONY: dirs $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

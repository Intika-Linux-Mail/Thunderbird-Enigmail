# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


DEPTH		= ..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/modules

DIRS = cryptoAPI

PREFFILES = prefs/defaultPrefs.js

ifeq ($(ENABLE_POSTBOX),yes)
PEPJSM = pEp-nonfunc.jsm
else
PEPJSM = pEp.jsm
endif

MODFILES = \
           addrbook.jsm \
           amPrefsService.jsm \
           app.jsm \
           armor.jsm \
           attachment.jsm \
           autocrypt.jsm \
           autoSetup.jsm \
           card.jsm \
           clipboard.jsm \
           commandLine.jsm \
           configBackup.jsm \
           configure.jsm \
           constants.jsm \
           core.jsm \
           cryptoAPI.jsm \
           data.jsm \
           decryption.jsm \
           persistentCrypto.jsm \
           dialog.jsm \
           enigmailOverlays.jsm \
           errorHandling.jsm \
           events.jsm \
           execution.jsm \
           dns.jsm \
           funcs.jsm \
           files.jsm \
           filters.jsm \
           filtersWrapper.jsm \
           fixExchangeMsg.jsm \
           gpgAgent.jsm \
           gnupgUpdate.jsm \
           glodaUtils.jsm \
           gpg.jsm \
           hash.jsm \
           httpProxy.jsm \
           installGnuPG.jsm \
           installPep.jsm \
           key.jsm \
           keyEditor.jsm \
           keyRing.jsm \
           keyObj.jsm \
           keyUsability.jsm \
           keyRefreshService.jsm \
           keyserver.jsm \
           keyserverUris.jsm \
           lazy.jsm \
           locale.jsm \
           localizeHtml.jsm \
           log.jsm \
           mime.jsm \
           mimeDecrypt.jsm \
           mimeEncrypt.jsm \
           mimeVerify.jsm \
           msgRead.jsm \
           os.jsm \
           openpgp.jsm \
           overlays.jsm \
           passwordCheck.jsm \
           passwords.jsm \
           $(PEPJSM) \
           pEpAdapter.jsm \
           pEpDecrypt.jsm \
           pEpFilter.jsm \
           pEpListener.jsm \
           pEpKeySync.jsm \
           pgpmimeHandler.jsm \
           pipeConsole.jsm \
           prefs.jsm \
           protocolHandler.jsm \
           rng.jsm \
           rules.jsm \
           searchCallback.jsm \
           send.jsm \
           singletons.jsm \
           socks5Proxy.jsm \
           sqliteDb.jsm \
           stdlib.jsm \
           streams.jsm \
           system.jsm \
           compat.jsm \
           time.jsm \
           timer.jsm \
           tor.jsm \
           trust.jsm \
           uris.jsm \
           verify.jsm \
           versioning.jsm \
           webKey.jsm \
           wkdLookup.jsm \
           windows.jsm \
           wksMimeHandler.jsm \
           xhrUtils.jsm \
           zbase32.jsm

DATE_FMT = +%Y%m%d-%H%M
SOURCE_DATE_EPOCH ?= $(shell date +%s)

# first try GNU /bin/date syntax; if that doesn't work, try BSD
# /bin/date syntax.  If that still fails, ignore SOURCE_DATE_EPOCH
ENIG_BUILD_DATE=$(shell TZ=UTC date $(DATE_FMT) -d "@$(SOURCE_DATE_EPOCH)" 2>/dev/null || \
                        TZ=UTC date -r "$(SOURCE_DATE_EPOCH)" $(DATE_FMT) || \
                        TZ=UTC date $(DATE_FMT) )

GENFILES = $(addprefix $(GENDIR)/,$(MODFILES))

$(GENDIR)/%.jsm: %.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) $< $@

all: dirs build deploy

build: $(GENFILES)

deploy: $(PREFFILES)
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/preferences $(PREFFILES)
	echo '"use strict";' > $(DIST)/chrome/content/modules/buildDate.jsm
	echo 'var EXPORTED_SYMBOLS = ["EnigmailBuildDate"];' >> $(DIST)/chrome/content/modules/buildDate.jsm
	echo 'var EnigmailBuildDate = { built: "$(ENIG_BUILD_DATE)" };' >> $(DIST)/chrome/content/modules/buildDate.jsm
	$(DEPTH)/util/prepPostbox $(TARGET_TOOL) bootstrap.js $(DIST)/bootstrap.js
	$(DEPTH)/util/prepPackage $(XPI_MODULE_VERS) $(DIST)


clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/preferences $(PREFFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content/modules $(MODFILES)
	$(DEPTH)/util/install -u $(DIST) bootstrap.js manifest.json install.rdf chrome.manifest

.PHONY: dirs $(DIRS)

dirs: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DEPTH  = ../..

include $(DEPTH)/config/autoconf.mk

GENDIR = $(DIST)/chrome/content/ui

AM_FILES = am-enigprefs.xul

UIFILES = \
	autocryptInitiateBackup.xul \
	autocryptInitiateBackup.js \
	autocryptSetupPasswd.xul \
	autocryptSetupPasswd.js \
	columnOverlay.xul \
	columnOverlay.js \
	commonWorkflows.js \
	enigmailCommon.js \
	enigmailAbCardViewOverlay.xul \
	enigmailAbContactsPanel.xul \
	enigmailAbOverlay.js \
	aboutEnigmail.html \
	aboutEnigmail.js \
	enigmailAddUidDlg.js \
	enigmailAddUidDlg.xul \
	enigmailMsgBox.js \
	enigmailMsgBox.xul \
	enigmailAttachmentsDialog.xul \
	enigmailAttachmentsDialog.js \
	enigmailAmIdEditOverlay.xul \
	enigmailCheckLanguage.xul \
	enigmailCardDetails.js \
	enigmailCardDetails.xul \
	enigmailConsole.xul \
	enigmailConsole.js \
	enigmailConsole.htm \
	enigmailCustToolOverlay.xul \
	enigmailDispPhoto.js \
	enigmailDispPhoto.xul \
	enigmailEditIdentity.js \
	enigmailEditIdentity.xul \
	enigmailEditKeyExpiryDlg.js \
	enigmailEditKeyExpiryDlg.xul \
	enigmailEditKeyTrustDlg.js \
	enigmailEditKeyTrustDlg.xul \
	enigmailEncryptionDlg.xul \
	enigmailEncryptionDlg.js \
	enigmailGenCardKey.js \
	enigmailGenCardKey.xul \
	enigmailGenericDisplay.js \
	enigmailGenericDisplay.xul \
	enigmailGenericDisplay.htm \
	enigmailHelp.xul \
	enigmailHelp.js \
	enigmailImportPhoto.js \
	enigmailImportPhoto.xul \
	keyDetailsDlg.js \
	keyDetailsDlg.xul \
	enigmailKeyManager.xul \
	enigmailKeyManager.js \
	enigmailManageUidDlg.js \
	enigmailManageUidDlg.xul \
	enigmailRulesEditor.xul \
	enigmailRulesEditor.js \
	enigmailSearchKey.js \
	enigmailSearchKey.xul \
	enigmailKeyImportInfo.js \
	enigmailKeyImportInfo.xul \
	enigmailSingleRcptSettings.js \
	enigmailSingleRcptSettings.xul \
	enigmailSelectRule.js \
	enigmailSelectRule.xul \
	enigmailSetCardPin.js \
	enigmailSetCardPin.xul \
	enigmailSignKeyDlg.js \
	enigmailSignKeyDlg.xul \
	accountManagerOverlay.js \
	accountManagerOverlay.xul \
	pref-enigmail.xul \
	pref-enigmail.js \
	pref-pep.xul \
	pref-pep.js \
	am-enigprefs.xul \
	am-enigprefs.js \
	editSingleAccount.xul \
	enigmailKeygen.xul \
	enigmailKeygen.js \
	enigmailKeygenConsole.htm \
	enigmailKeyserverDlg.xul \
	enigmailKeyserverDlg.js \
	enigmailKeySelection.xul \
	enigmailKeySelection.js \
	enigmailMsgComposeOverlay.xul \
	enigmailMsgComposeOverlay-pbx.xul \
	enigmailMsgComposeOverlay.js \
	enigmailMsgComposeHelper.js \
	messengerOverlay-tbird.xul \
	messengerOverlay-pbx.xul \
	enigmailMessengerOverlay.xul \
	enigmailMessengerOverlay.js \
	enigmailMsgHdrViewOverlay.xul \
	enigmailMsgHdrViewOverlay.js \
	enigmailFilterEditorOverlay.xul \
	enigmailFilterEditorOverlay.js \
	enigmailFilterListOverlay.xul \
	enigmailFilterListOverlay.js \
	enigmailPrivacyOverlay.js \
	enigmailPrivacyOverlay.xul \
	enigmailWrapSelection.xul \
	enigmailWrapSelection.js \
	enigmailViewFile.js \
	enigmailViewFile.xul \
	enigRetrieveProgress.xul \
	enigRetrieveProgress.js \
	exportSettingsWizard.js \
	exportSettingsWizard.xul \
	importSettings.js \
	importSettings.xul \
	upgradeInfo.html \
	pepHandshake.xul \
	pepHandshake.js \
	pepPrepHandshake.xul \
	pepPrepHandshake.js \
	pepTrustWords.xul \
	pepTrustWords.js \
	updateGnuPG.html \
	updateGnuPG.js \
	setupWizard2.js \
	setupWizard2.xul \
	tb60FilterEditorOverlay.js \
	tb60FilterEditorOverlay.xul

GENFILES = $(addprefix $(GENDIR)/,$(UIFILES))

$(GENDIR)/%.js: %.js
	$(DEPTH)/util/prepPostbox -c $(TARGET_TOOL) $< $@

$(GENDIR)/%.xul: %.xul
	$(PERL) $(DEPTH)/util/plpp.pl -i $(INCLUDE) -o $@ $<

$(GENDIR)/%.htm: %.htm
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $<

$(GENDIR)/%.html: %.html
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content/ui $<

all: build deploy

build: $(GENFILES)
	
deploy: $(AM_FILES)
	$(DEPTH)/util/install -m 644 $(DIST)/chrome/content $(AM_FILES)

clean:
	$(DEPTH)/util/install -u $(DIST)/chrome/content/ui $(UIFILES)
	$(DEPTH)/util/install -u $(DIST)/chrome/content $(AM_FILES)

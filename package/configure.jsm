/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*global Components: false */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailConfigure"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;


/*global EnigmailLog: false, EnigmailPrefs: false, EnigmailTimer: false, EnigmailApp: false, EnigmailLocale: false, EnigmailDialog: false, EnigmailWindows: false */

Cu.import("chrome://enigmail/content/modules/log.jsm");
Cu.import("chrome://enigmail/content/modules/prefs.jsm");
Cu.import("chrome://enigmail/content/modules/timer.jsm");
Cu.import("chrome://enigmail/content/modules/app.jsm");
Cu.import("chrome://enigmail/content/modules/locale.jsm");
Cu.import("chrome://enigmail/content/modules/dialog.jsm");
Cu.import("chrome://enigmail/content/modules/windows.jsm");
Cu.import("chrome://enigmail/content/modules/core.jsm"); /* global EnigmailCore: false */
Cu.import("chrome://enigmail/content/modules/pEpAdapter.jsm"); /* global EnigmailPEPAdapter: false */
Cu.import("chrome://enigmail/content/modules/installPep.jsm"); /* global EnigmailInstallPep: false */
Cu.import("chrome://enigmail/content/modules/stdlib.jsm"); /* global EnigmailStdlib: false */
Cu.import("chrome://enigmail/content/modules/lazy.jsm"); /* global EnigmailLazy: false */

// Interfaces
const nsIFolderLookupService = Ci.nsIFolderLookupService;
const nsIMsgAccountManager = Ci.nsIMsgAccountManager;
const nsIMsgAccount = Ci.nsIMsgAccount;
const nsIMsgDBHdr = Ci.nsIMsgDBHdr;
const nsIMessenger = Ci.nsIMessenger;
const nsIMsgMessageService = Ci.nsIMsgMessageService;
const nsIMsgFolder = Ci.nsIMsgFolder;


/**
 * Upgrade sending prefs
 * (v1.6.x -> v1.7 )
 */
function upgradePrefsSending() {
  EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending()\n");

  var cbs = EnigmailPrefs.getPref("confirmBeforeSend");
  var ats = EnigmailPrefs.getPref("alwaysTrustSend");
  var ksfr = EnigmailPrefs.getPref("keepSettingsForReply");
  EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending cbs=" + cbs + " ats=" + ats + " ksfr=" + ksfr + "\n");

  // Upgrade confirmBeforeSend (bool) to confirmBeforeSending (int)
  switch (cbs) {
    case false:
      EnigmailPrefs.setPref("confirmBeforeSending", 0); // never
      break;
    case true:
      EnigmailPrefs.setPref("confirmBeforeSending", 1); // always
      break;
  }

  // Upgrade alwaysTrustSend (bool)   to acceptedKeys (int)
  switch (ats) {
    case false:
      EnigmailPrefs.setPref("acceptedKeys", 0); // valid
      break;
    case true:
      EnigmailPrefs.setPref("acceptedKeys", 1); // all
      break;
  }

  // if all settings are default settings, use convenient encryption
  if (cbs === false && ats === true && ksfr === true) {
    EnigmailPrefs.setPref("encryptionModel", 0); // convenient
    EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending() encryptionModel=0 (convenient)\n");
  }
  else {
    EnigmailPrefs.setPref("encryptionModel", 1); // manually
    EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending() encryptionModel=1 (manually)\n");
  }

  // clear old prefs
  EnigmailPrefs.getPrefBranch().clearUserPref("confirmBeforeSend");
  EnigmailPrefs.getPrefBranch().clearUserPref("alwaysTrustSend");
}

/**
 * Replace short key IDs with FPR in identity settings
 * (v1.9 -> v2.0)
 */
function replaceKeyIdWithFpr() {
  try {
    const GetKeyRing = EnigmailLazy.loader("enigmail/keyRing.jsm", "EnigmailKeyRing");

    var accountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(Ci.nsIMsgAccountManager);
    for (var i = 0; i < accountManager.allIdentities.length; i++) {
      var id = accountManager.allIdentities.queryElementAt(i, Ci.nsIMsgIdentity);
      if (id.getBoolAttribute("enablePgp")) {
        let keyId = id.getCharAttribute("pgpkeyId");

        if (keyId.search(/^(0x)?[a-fA-F0-9]{8}$/) === 0) {

          EnigmailCore.getService();

          let k = GetKeyRing().getKeyById(keyId);
          if (k) {
            id.setCharAttribute("pgpkeyId", "0x" + k.fpr);
          }
          else {
            id.setCharAttribute("pgpkeyId", "");
          }
        }
      }
    }
  }
  catch (ex) {
    EnigmailDialog.alert("config upgrade: error" + ex.toString());
  }
}


/**
 * Change the default to PGP/MIME for all accounts, except nntp
 * (v1.8.x -> v1.9)
 */
function defaultPgpMime() {
  let accountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(Ci.nsIMsgAccountManager);
  let changedSomething = false;

  for (let acct = 0; acct < accountManager.accounts.length; acct++) {
    let ac = accountManager.accounts.queryElementAt(acct, Ci.nsIMsgAccount);
    if (ac.incomingServer.type.search(/(pop3|imap|movemail)/) >= 0) {

      for (let i = 0; i < ac.identities.length; i++) {
        let id = ac.identities.queryElementAt(i, Ci.nsIMsgIdentity);
        if (id.getBoolAttribute("enablePgp") && !id.getBoolAttribute("pgpMimeMode")) {
          changedSomething = true;
        }
        id.setBoolAttribute("pgpMimeMode", true);
      }
    }
  }

  if (EnigmailPrefs.getPref("advancedUser") && changedSomething) {
    EnigmailDialog.alert(null,
      EnigmailLocale.getString("preferences.defaultToPgpMime"));
  }
}

/**
 * set the Autocrypt prefer-encrypt option to "mutual" for all existing
 * accounts
 */
function setAutocryptForOldAccounts() {
  try {
    let accountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(Ci.nsIMsgAccountManager);
    let changedSomething = false;

    for (let acct = 0; acct < accountManager.accounts.length; acct++) {
      let ac = accountManager.accounts.queryElementAt(acct, Ci.nsIMsgAccount);
      if (ac.incomingServer.type.search(/(pop3|imap|movemail)/) >= 0) {
        ac.incomingServer.setIntValue("acPreferEncrypt", 1);
      }
    }
  }
  catch (ex) {}
}


/**
 * Determine if pEp is avaliable, and if it is not available,
 * whether it can be downaloaded and installed. This does not
 * trigger installation.
 */

function isPepInstallable() {
  if (EnigmailPEPAdapter.isPepAvailable(false)) {
    return true;
  }

  return EnigmailInstallPep.isPepInstallerAvailable();
}

function displayUpgradeInfo() {
  EnigmailLog.DEBUG("configure.jsm: displayUpgradeInfo()\n");
  try {
    EnigmailWindows.openMailTab("chrome://enigmail/content/ui/upgradeInfo.html");
  }
  catch (ex) {}
}

// Util Function for Extracting manually added Headers
function streamListener()
{
  var newStreamListener = {
    mAttachments: [],
    mHeaders:     [],
    mBusy:        true,

    onStartRequest : function (aRequest, aContext)
    {
      this.mAttachments = [];
      this.mHeaders     = [];
      this.mBusy        = true;

      var channel = aRequest.QueryInterface(Components.interfaces.nsIChannel);
      channel.URI.QueryInterface(Components.interfaces.nsIMsgMailNewsUrl);
      channel.URI.msgHeaderSink = this;  // adds this header sink interface to the channel
    },
    onStopRequest : function (aRequest, aContext, aStatusCode)
    {
      this.mBusy = false;  // if needed, you can poll this var to see if we are done collecting attachment details
    },
    onDataAvailable : function (aRequest, aContext, aInputStream, aOffset, aCount) {},
    onStartHeaders: function() {},
    onEndHeaders: function() {},
    processHeaders: function(aHeaderNameEnumerator, aHeaderValueEnumerator, aDontCollectAddress)
    {
      while (aHeaderNameEnumerator.hasMore())
        this.mHeaders.push({name:aHeaderNameEnumerator.getNext().toLowerCase(), value:aHeaderValueEnumerator.getNext()});
    },
    handleAttachment: function(aContentType, aUrl, aDisplayName, aUri, aIsExternalAttachment)
    {
      if (aContentType == "text/html") return;
      this.mAttachments.push({contentType:aContentType, url:aUrl, displayName:aDisplayName, uri:aUri, isExternal:aIsExternalAttachment});
    },
    onEndAllAttachments: function() {},
    onEndMsgDownload: function(aUrl) {},
    onEndMsgHeaders: function(aUrl) {},
    onMsgHasRemoteContent: function(aMsgHdr) {},
    getSecurityInfo: function() {},
    setSecurityInfo: function(aSecurityInfo) {},
    getDummyMsgHeader: function() {},

    QueryInterface : function(aIID)
    {
      if (aIID.equals(Components.interfaces.nsIStreamListener) ||
          aIID.equals(Components.interfaces.nsIMsgHeaderSink) ||
          aIID.equals(Components.interfaces.nsISupports))
        return this;

      throw Components.results.NS_NOINTERFACE;
      return 0;
    }
  };

  return newStreamListener;
}

// Util Function to identify which function to perform on start up
function getMsgHeader() {

    getEnigmailLog().DEBUG("configure.jsm: getMsgHeader()\n");

    let msgAccountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(nsIMsgAccountManager);
    let folderService = Cc["@mozilla.org/mail/folder-lookup;1"].getService(nsIFolderLookupService);
    let returnMsgValue = {
        value: 3
    }

    var accounts = msgAccountManager.accounts;

    let autocryptHeaders = [];
    let autocryptSetupMessage = {};

    // Ierating through each account

    for (var i = 0; i < accounts.length; i++) {
        var account = accounts.queryElementAt(i, nsIMsgAccount);
        var accountMsgServer = account.incomingServer;
        gFolderURIs.push(accountMsgServer.serverURI);

        let rootFolder = folderService.getFolderForURL(gFolderURIs[i]);

        if (rootFolder == null) {
            break;
        }

        let msgFolders = [];

        msgFolders.push(rootFolder);

        // To list all the Folder in Main Account Folder

        var j = 0;

        while (msgFolders.length > j) {

            let containFolder = msgFolders[j];

            if (containFolder.hasSubFolders) {
                let subFolders = containFolder.subFolders;
                while (subFolders.hasMoreElements()) {
                    msgFolders.push(subFolders.getNext().QueryInterface(nsIMsgFolder));
                }
            }
            j++;

        }

        // Iterating through each Folder in the Account

        for (var k = 0; k < msgFolders.length; k++) {
            let msgFolder = msgFolders[k];

            let msgDatabase = msgFolder.msgDatabase;

            if (msgDatabase != null) {
                let msgEnumerator = msgDatabase.ReverseEnumerateMessages();

                // Iterating through each message in the Folder

                while (msgEnumerator.hasMoreElements()) {

                    let msgHeader = msgEnumerator.getNext().QueryInterface(nsIMsgDBHdr);
                    let msgURI = msgFolder.getUriForMsg(msgHeader);

                    // Listing all the headers in the message

                    var messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(nsIMessenger);
                    var mms = messenger.messageServiceFromURI(msgURI).QueryInterface(nsIMsgMessageService);
                    var listener = streamListener();
                    mms.streamMessage(msgURI, listener, null, null, true, "filter");

                    //lazy async, wait for listener
                    let thread = Components.classes["@mozilla.org/thread-manager;1"].getService().currentThread;
                    while (listener.mBusy) {
                        thread.processNextEvent(true);
                    }

                    // Store all headers in the mData-variable
                    for (var i = 0; i < listener.mHeaders.length; i++) {
                        var name = listener.mHeaders[i].name;
                        var value = listener.mHeaders[i].value;
                        if(name == 'autocrypt-setup-message' && value == 'v1' && msgHeader.author == msgHeader.recipients){
                            if(!returnMsgValue.header){
                                returnMsgValue.value = 1;
                                returnMsgValue.header = msgHeader;
                            }
                            else if(returnMsgValue.header.date < msgHeader.date){
                                returnMsgValue.header = msgHeader;
                            }
                        }
                        else if(name == 'autocrypt'){
                            if(!autocryptHeaders.includes(value[0])){
                                autocryptHeaders.push(value[0]);
                            }
                        }

                    }

                    const currDateInSeconds = new Date().getTime() / 1000;
                    const diffSecond = currDateInSeconds - msgHeader.dateInSeconds;

                    /**
                        2592000 = No. of Seconds in a Month.
                        This is to ignore 1 month old messages.
                    */
                    if (diffSecond > 2592000.0) {
                        break;
                    }
                }
            }

        }

    }

    if(returnMsgValue.header){
        return returnMsgValue;
    }

    if (autocryptHeaders.length > 0) {
        returnMsgValue.value = 2;
        returnMsgValue.autocryptheaders = autocryptHeaders;
    }

    return returnMsgValue;
}


var EnigmailConfigure = {
  configureEnigmail: function(win, startingPreferences) {
    EnigmailLog.DEBUG("configure.jsm: configureEnigmail()\n");

    if (!EnigmailStdlib.hasConfiguredAccounts()) {
      EnigmailLog.DEBUG("configure.jsm: configureEnigmail: no account configured. Waiting 60 seconds.\n");

      // try again in 60 seconds
      EnigmailTimer.setTimeout(
        function _f() {
          EnigmailConfigure.configureEnigmail(win, startingPreferences);
        },
        60000);
      return;
    }

    let oldVer = EnigmailPrefs.getPref("configuredVersion");

    let vc = Cc["@mozilla.org/xpcom/version-comparator;1"].getService(Ci.nsIVersionComparator);

    if (oldVer === "") {
      EnigmailPrefs.setPref("configuredVersion", EnigmailApp.getVersion());

      let headerValue = getMsgHeader();

      if(headerValue.value == 1){
        // Notify Autocrypt Setup Message Found and Open that(Latest)
      }
      else if(headerValue.value == 2){
        // Notify messages with autocrypt header found and store keys accordingly
      }

      else if(headerValue.value == 3){
        // Create a new Key associated with default account and Notify user that key is made.
      }


      if (EnigmailPrefs.getPref("juniorMode") === 0 || (!isPepInstallable())) {
        // start wizard if pEp Junior Mode is forced off or if pep cannot
        // be installed/used
        EnigmailWindows.openSetupWizard(win, false);
      }
    }
    else {
      if (vc.compare(oldVer, "1.7a1pre") < 0) {
        // 1: rules only
        //     => assignKeysByRules true; rest false
        // 2: rules & email addresses (normal)
        //     => assignKeysByRules/assignKeysByEmailAddr/assignKeysManuallyIfMissing true
        // 3: email address only (no rules)
        //     => assignKeysByEmailAddr/assignKeysManuallyIfMissing true
        // 4: manually (always prompt, no rules)
        //     => assignKeysManuallyAlways true
        // 5: no rules, no key selection
        //     => assignKeysByRules/assignKeysByEmailAddr true

        upgradePrefsSending();
      }
      if (vc.compare(oldVer, "1.7") < 0) {
        // open a modal dialog. Since this might happen during the opening of another
        // window, we have to do this asynchronously
        EnigmailTimer.setTimeout(
          function _cb() {
            var doIt = EnigmailDialog.confirmDlg(win,
              EnigmailLocale.getString("enigmailCommon.versionSignificantlyChanged"),
              EnigmailLocale.getString("enigmailCommon.checkPreferences"),
              EnigmailLocale.getString("dlg.button.close"));
            if (!startingPreferences && doIt) {
              // same as:
              // - EnigmailWindows.openPrefWindow(window, true, 'sendingTab');
              // but
              // - without starting the service again because we do that right now
              // - and modal (waiting for its end)
              win.openDialog("chrome://enigmail/content/ui/pref-enigmail.xul",
                "_blank", "chrome,resizable=yes,modal", {
                  'showBasic': true,
                  'clientType': 'thunderbird',
                  'selectTab': 'sendingTab'
                });
            }
          }, 100);
      }

      if (vc.compare(oldVer, "1.9a2pre") < 0) {
        defaultPgpMime();
      }
      if (vc.compare(oldVer, "2.0a1pre") < 0) {
        this.upgradeTo20();
      }
      if (vc.compare(oldVer, "2.0.1a2pre") < 0) {
        this.upgradeTo201();
      }
    }

    EnigmailPrefs.setPref("configuredVersion", EnigmailApp.getVersion());
    EnigmailPrefs.savePrefs();
  },

  upgradeTo20: function() {
    EnigmailPrefs.setPref("juniorMode", 0); // disable pEp if upgrading from older version
    replaceKeyIdWithFpr();
    displayUpgradeInfo();
  },

  upgradeTo201: function() {
    setAutocryptForOldAccounts();
  }
};

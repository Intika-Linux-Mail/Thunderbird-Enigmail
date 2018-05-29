/*global Components: false*/
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

/**
 *  Module for dealing with received Autocrypt headers, level 0
 *  See details at https://github.com/mailencrypt/autocrypt
 */

var EXPORTED_SYMBOLS = ["EnigmailAutocryptSetup"];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("chrome://enigmail/content/modules/log.jsm"); /* global EnigmailLog: false*/
Cu.import("chrome://enigmail/content/modules/locale.jsm"); /* global EnigmailLocale: false*/
Cu.import("chrome://enigmail/content/modules/autocrypt.jsm"); /* global EnigmailAutocrypt: false*/
Cu.import("chrome://enigmail/content/modules/windows.jsm"); /* global EnigmailWindows: false*/
Cu.import("chrome://enigmail/content/modules/dialog.jsm"); /* global EnigmailDialog: false*/


// Interfaces
const nsIFolderLookupService = Ci.nsIFolderLookupService;
const nsIMsgAccountManager = Ci.nsIMsgAccountManager;
const nsIMsgAccount = Ci.nsIMsgAccount;
const nsIMsgDBHdr = Ci.nsIMsgDBHdr;
const nsIMessenger = Ci.nsIMessenger;
const nsIMsgMessageService = Ci.nsIMsgMessageService;
const nsIMsgFolder = Ci.nsIMsgFolder;

let console = (Cu.import("resource://gre/modules/Console.jsm", {})).console;


var gFolderURIs = [];

var EnigmailAutocryptSetup = {
     /**
       * Identify the case at the time of installation, 1) Autocrypt Setup Message Found 2) Sent Message with Autocrypt header Found 3)None of the above
       *
       *
       *
       * @return Object with Headers(Optional), value : For each case assigned value,
    */
    getMsgHeader: function(){

      EnigmailLog.DEBUG("autocryptSetup.jsm: getMsgHeader()\n");

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
                if (name == 'autocrypt-setup-message' && value == 'v1' && msgHeader.author == msgHeader.recipients) {
                  if (!returnMsgValue.header) {
                    returnMsgValue.value = 1;
                    returnMsgValue.header = msgHeader;
                    returnMsgValue.attachment = listener.mAttachments[0];
                  } else if (returnMsgValue.header.date < msgHeader.date) {
                    returnMsgValue.header = msgHeader;
                    returnMsgValue.attachment = listener.mAttachments[0];
                  }
                } else if (name == 'autocrypt') {
                  if (!autocryptHeaders.includes(value[0])) {
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

      if (returnMsgValue.header) {
        return returnMsgValue;
      }

      if (autocryptHeaders.length > 0) {
        returnMsgValue.value = 2;
        returnMsgValue.autocryptheaders = autocryptHeaders;
      }

      return returnMsgValue;
    },

     /**
       * Process the Autocrypt Setup Message
       *
       * @param headerValue:      Object - containing header and attachment of the latest Autocrypt Setup Message
       *
     */

    performAutocryptSetup: function(headerValue) {
      EnigmailLog.DEBUG("autocryptSetup.js: performAutocryptSetup()");
      if (headerValue.attachment.contentType.search(/^application\/autocrypt-setup$/i) === 0) {

        EnigmailAutocrypt.getSetupMessageData(headerValue.attachment.url).then(res => {
          let passwd = EnigmailWindows.autocryptSetupPasswd(null, "input", res.passphraseFormat, res.passphraseHint);

          if ((!passwd) || passwd == "") {
            throw "noPasswd";
          }

          return EnigmailAutocrypt.handleBackupMessage(passwd, res.attachmentData, headerValue.header.author);
        }).
        then(res => {
          EnigmailDialog.info(null, EnigmailLocale.getString("autocrypt.importSetupKey.success", headerValue.header.author));
        }).
        catch(err => {
          console.log(err);
          EnigmailLog.DEBUG("autocryptSetup.js: performAutocryptSetup got cancel status=" + err + "\n");

          switch (err) {
            case "getSetupMessageData":
              EnigmailDialog.alert(window, EnigmailLocale.getString("autocrypt.importSetupKey.invalidMessage"));
              break;
            case "wrongPasswd":
              if (EnigmailDialog.confirmDlg(window, EnigmailLocale.getString("autocrypt.importSetupKey.wrongPasswd"), EnigmailLocale.getString("dlg.button.retry"),
                  EnigmailLocale.getString("dlg.button.cancel"))) {
                performAutocryptSetup(headerValue);
              }
              break;
            case "keyImportFailed":
              EnigmailDialog.alert(window, EnigmailLocale.getString("autocrypt.importSetupKey.invalidKey"));
              break;
          }
        });
      }
    }
};

// Util Function for Extracting manually added Headers
function streamListener() {
  var newStreamListener = {
    mAttachments: [],
    mHeaders: [],
    mBusy: true,

    onStartRequest: function(aRequest, aContext) {
      this.mAttachments = [];
      this.mHeaders = [];
      this.mBusy = true;

      var channel = aRequest.QueryInterface(Components.interfaces.nsIChannel);
      channel.URI.QueryInterface(Components.interfaces.nsIMsgMailNewsUrl);
      channel.URI.msgHeaderSink = this; // adds this header sink interface to the channel
    },
    onStopRequest: function(aRequest, aContext, aStatusCode) {
      this.mBusy = false; // if needed, you can poll this var to see if we are done collecting attachment details
    },
    onDataAvailable: function(aRequest, aContext, aInputStream, aOffset, aCount) {},
    onStartHeaders: function() {},
    onEndHeaders: function() {},
    processHeaders: function(aHeaderNameEnumerator, aHeaderValueEnumerator, aDontCollectAddress) {
      while (aHeaderNameEnumerator.hasMore())
        this.mHeaders.push({
          name: aHeaderNameEnumerator.getNext().toLowerCase(),
          value: aHeaderValueEnumerator.getNext()
        });
    },
    handleAttachment: function(aContentType, aUrl, aDisplayName, aUri, aIsExternalAttachment) {
      if (aContentType == "text/html") return;
      this.mAttachments.push({
        contentType: aContentType,
        url: aUrl,
        displayName: aDisplayName,
        uri: aUri,
        isExternal: aIsExternalAttachment
      });
    },
    onEndAllAttachments: function() {},
    onEndMsgDownload: function(aUrl) {},
    onEndMsgHeaders: function(aUrl) {},
    onMsgHasRemoteContent: function(aMsgHdr) {},
    getSecurityInfo: function() {},
    setSecurityInfo: function(aSecurityInfo) {},
    getDummyMsgHeader: function() {},

    QueryInterface: function(aIID) {
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
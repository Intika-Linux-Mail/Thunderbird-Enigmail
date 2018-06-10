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
Cu.import("chrome://enigmail/content/modules/autocrypt.jsm"); /* global EnigmailAutocrypt: false*/
Cu.import("chrome://enigmail/content/modules/keyRing.jsm"); /* global EnigmailKeyRing: false*/
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

// Interfaces
const nsIFolderLookupService = Ci.nsIFolderLookupService;
const nsIMsgAccountManager = Ci.nsIMsgAccountManager;
const nsIMsgAccount = Ci.nsIMsgAccount;
const nsIMsgDBHdr = Ci.nsIMsgDBHdr;
const nsIMessenger = Ci.nsIMessenger;
const nsIMsgMessageService = Ci.nsIMsgMessageService;
const nsIMsgFolder = Ci.nsIMsgFolder;

var gFolderURIs = [];

var EnigmailAutocryptSetup = {
     /**
       * Identify the case at the time of installation, 1) Autocrypt Setup Message Found 2) Sent Message with Autocrypt header Found 3)None of the above
       *
       *
       *
       * @return Object with Headers(Optional), value : For each case assigned value,
    */
    getMsgHeader: async function(){

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

        let msgObject = getMsgFolders(rootFolder);

        // Iterating through each Folder Database in the Account

        for (var k = 0; k < msgObject.length; k++) {

          let msgDatabase = msgObject[k].msgDatabase;
          let msgFolder = msgObject[k].msgFolder;

          let msgEnumerator = msgDatabase.ReverseEnumerateMessages();

          // Iterating through each message in the Folder
          while (msgEnumerator.hasMoreElements()) {
            let msgHeader = msgEnumerator.getNext().QueryInterface(nsIMsgDBHdr);
            let msgURI = msgFolder.getUriForMsg(msgHeader);

            let msgAuthor = msgHeader.author.substring(msgHeader.author.lastIndexOf("<") + 1, msgHeader.author.lastIndexOf(">"));

            // Listing all the headers in the message

            var messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(nsIMessenger);
            var mms = messenger.messageServiceFromURI(msgURI).QueryInterface(nsIMsgMessageService);

            let headerObj = await getStreamedHeaders(msgURI, mms);

            let checkHeaderValues = checkHeaders(headerObj, msgHeader, msgAuthor, accountMsgServer, returnMsgValue, autocryptHeaders);

            autocryptHeaders = checkHeaderValues.autocryptHeaders;
            returnMsgValue = checkHeaderValues.returnMsgValue;

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

      if (returnMsgValue.header) {
        return returnMsgValue;
      }

      if (autocryptHeaders.length > 0) {
        returnMsgValue.value = 2;
        returnMsgValue.autocryptheaders = autocryptHeaders;
      }

      returnMsgValue.userName = msgAccountManager.defaultAccount.defaultIdentity.fullName;
      returnMsgValue.userEmail = msgAccountManager.defaultAccount.defaultIdentity.email;

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
          EnigmailLog.DEBUG("autocryptSetup.js: performAutocryptSetup got cancel status=" + err + "\n");

          switch (err) {
            case "getSetupMessageData":
              EnigmailDialog.alert(null, EnigmailLocale.getString("autocrypt.importSetupKey.invalidMessage"));
              break;
            case "wrongPasswd":
              if (EnigmailDialog.confirmDlg(null, EnigmailLocale.getString("autocrypt.importSetupKey.wrongPasswd"), EnigmailLocale.getString("dlg.button.retry"),
                  EnigmailLocale.getString("dlg.button.cancel"))) {
                EnigmailAutocryptSetup.performAutocryptSetup(headerValue);
              }
              break;
            case "keyImportFailed":
              EnigmailDialog.alert(null, EnigmailLocale.getString("autocrypt.importSetupKey.invalidKey"));
              break;
          }
        });
      }
    },

    /**
        * Process the Autocrypt Setup Message
        *
        * @param headerValue:      Object - containing distinct Autocrypt headers from all the sent mails
        *
    */

    processAutocryptHeader : function(headerValue){
        EnigmailLog.DEBUG("autocryptSetup.js: processAutocryptHeader()");
        for (let i = 0; i < headerValue.autocryptheaders.length; i++) {
          for (let j = 0; j < headerValue.autocryptheaders[i].msgData.length; j++) {
            let success = EnigmailAutocrypt.processAutocryptHeader(headerValue.autocryptheaders[i].fromAddr, [headerValue.autocryptheaders[i].msgData[j]], headerValue.autocryptheaders[i].date);
            let check = 0;
            success.then((value) => {
              if (value != 0) {
                EnigmailDialog.alert(null, EnigmailLocale.getString("acStartup.acHeaderFound.failure"));
                check++;
              }
            });
            if(check != 0){
                return;
            }
          }
        }
        EnigmailDialog.alert(null, EnigmailLocale.getString("acStartup.acHeaderFound.success"));
    },

    startKeyGen : function(headerValue){
      EnigmailLog.DEBUG("autocryptSetup.js: startKeyGen()");
      let userName = headerValue.userName,
        userEmail = headerValue.userEmail,
        expiry = 1825,
        keyLength = 4096,
        keyType = "RSA",
        passphrase = "",
        generateObserver = new enigGenKeyObserver();

      try{
        EnigmailKeyRing.generateKey(userName, "", userEmail, expiry, keyLength, keyType, passphrase, generateObserver);
      }
      catch(ex) {
        EnigmailLog.DEBUG("autocryptSetup.js: startKeyGen() error : " + ex);
      }
    }
};


function createStreamListener(k) {
  return {
    _data: "",
    _stream: null,

    QueryInterface: XPCOMUtils.generateQI([Ci.nsIStreamListener, Ci.nsIRequestObserver]),

    // nsIRequestObserver
    onStartRequest: function(aRequest, aContext) {},
    onStopRequest: function(aRequest, aContext, aStatusCode) {
      try {
        k(this._data);
      }
      catch (e) {
        console.log("Error inside stream listener:\n" + e + "\n");
      }
    },

    // nsIStreamListener
    onDataAvailable: function(aRequest, aContext, aInputStream, aOffset, aCount) {
      if (this._stream == null) {
        this._stream = Cc["@mozilla.org/scriptableinputstream;1"].createInstance(Ci.nsIScriptableInputStream);
        this._stream.init(aInputStream);
      }
      this._data += this._stream.read(aCount);
    }
  };
}

function getMsgFolders(rootFolder){

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

  let msgFoldersDatabase = [];

  for (var i = 0; i < msgFolders.length; i++) {
    let msgDatabase = msgFolders[i].msgDatabase;
    if(msgDatabase != null){
        let msgEnumerator = msgDatabase.ReverseEnumerateMessages();
        if(msgEnumerator.hasMoreElements()){
            let msgObject = {
              'msgFolder' : msgFolders[i],
              'msgDatabase' : msgDatabase
            };
            msgFoldersDatabase.push(msgObject);
        }
    }

  }

  return msgFoldersDatabase;
}

function checkHeaders(headerObj, msgHeader, msgAuthor, accountMsgServer, returnMsgValue, autocryptHeaders){
  if (headerObj['autocrypt-setup-message'] && msgHeader.author == msgHeader.recipient) {
    if (!returnMsgValue.header) {
      returnMsgValue.value = 1;
      returnMsgValue.header = msgHeader;
      //returnMsgValue.attachment = listener.mAttachments[0];
    } else if (returnMsgValue.header.date < msgHeader.date) {
      returnMsgValue.header = msgHeader;
      //returnMsgValue.attachment = listener.mAttachments[0];
    }
  } else if (headerObj['autocrypt'] && msgAuthor == accountMsgServer.username) {
    if (autocryptHeaders.length == 0) {
      let addHeader = {
        'fromAddr': msgAuthor,
        'msgData': headerObj['autocrypt'],
        'date': headerObj['date'][0]
      }
      autocryptHeaders.push(addHeader);
    } else {
      let fromHeaderExist = 0;
      for (let j = 0; j < autocryptHeaders.length; j++) {
        if (autocryptHeaders[j].fromAddr == msgAuthor) {
          if (!autocryptHeaders[j].msgData.includes(headerObj['autocrypt'][0])) {
            autocryptHeaders[j].msgData.push(headerObj['autocrypt'][0]);
          }
          fromHeaderExist++;
          break;
        }
      }
      if (fromHeaderExist == 0) {
        let addHeader = {
          'fromAddr': msgAuthor,
          'msgData': headerObj['autocrypt'],
          'date': headerObj['date'][0]
        }
        autocryptHeaders.push(addHeader);
      }
    }
  }

  return {
    'returnMsgValue' : returnMsgValue,
    'autocryptHeaders' : autocryptHeaders
  }
}

function getStreamedHeaders(msgURI, mms) {

  return new Promise((resolve, reject) => {
     let headerObj = {};
     mms.streamHeaders(msgURI, createStreamListener(aRawString => {
       try {
         let re = '/\r?\n\s+/g';
         let str = aRawString.replace(re, " ");
         let lines = str.split(/\r?\n/);
         for (let line of lines) {
           let i = line.indexOf(":");
           if (i < 0)
             continue;
           let k = line.substring(0, i).toLowerCase();
           let v = line.substring(i + 1).trim();
           if (!(k in headerObj))
             headerObj[k] = [];
           headerObj[k].push(v);
         }
       } catch (e) {
         EnigmailLog.DEBUG("autocryptSetup.js: getStreamedHeaders() error : " + e + "\n");
       }
       resolve(headerObj)
     }), null, false);
  });

}

function enigGenKeyObserver() {}

enigGenKeyObserver.prototype = {
  keyId: null,
  backupLocation: null,
  _state: 0,

  onDataAvailable: function(data) {},
  onStopRequest: function(exitCode) {}
};
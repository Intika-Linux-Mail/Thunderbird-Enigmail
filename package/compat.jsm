/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

"use strict";

/**
 *  TB / Postbox compatibility Module
 */

var EXPORTED_SYMBOLS = ["EnigmailCompat"];

const POSTBOX_ID = "postbox@postbox-inc.com";
const XPCOM_APPINFO = "@mozilla.org/xre/app-info;1";

var gIsPostbox = null;
var MailUtils;

try {
  // Postbox / TB < 60
  MailUtils = ChromeUtils.import("resource:///modules/MailUtils.js").MailUtils;
}
catch (x) {
  // Thunderbird
  MailUtils = ChromeUtils.import("resource:///modules/MailUtils.jsm").MailUtils;
}

var gCompFields, gPgpMimeObj;

var EnigmailCompat = {
  generateQI: function(aCid) {
    if ("generateQI" in ChromeUtils) {
      // TB > 60
      return ChromeUtils.generateQI(aCid);
    } else {
      let XPCOMUtils = ChromeUtils.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;
      return XPCOMUtils.generateQI(aCid);
    }
  },

  getSecurityField: function() {
    if (!gCompFields) {
      gCompFields = Cc["@mozilla.org/messengercompose/composefields;1"].createInstance(Ci.nsIMsgCompFields);
    }
    return ("securityInfo" in gCompFields ? /* TB < 64 */ "securityInfo" : "composeSecure");
  },

  getExistingFolder: function(folderUri) {
    if ("getExistingFolder" in MailUtils) {
      // TB >= 65
      return MailUtils.getExistingFolder(folderUri);
    } else {
      return MailUtils.getFolderForURI(folderUri, false);
    }
  },

  isMessageUriInPgpMime: function() {
    if (!gPgpMimeObj) {
      gPgpMimeObj = Cc["@mozilla.org/mime/pgp-mime-js-decrypt;1"].createInstance(Ci.nsIPgpMimeProxy);
    }

    return ("messageURI" in gPgpMimeObj);
  },

  /**
   * return true, if platform is newer than or equal a given version
   */
  isPlatformNewerThan: function(requestedVersion) {
    let vc = Cc["@mozilla.org/xpcom/version-comparator;1"].getService(Ci.nsIVersionComparator);
    let appVer = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULAppInfo).platformVersion;

    return vc.compare(appVer, requestedVersion) >= 0;
  },

  /**
   * Get a mail URL from a uriSpec
   *
   * @param uriSpec: String - URI of the desired message
   *
   * @return Object: nsIURL or nsIMsgMailNewsUrl object
   */
  getUrlFromUriSpec: function(uriSpec) {
    try {
      if (!uriSpec)
        return null;

      let messenger = Cc["@mozilla.org/messenger;1"].getService(Ci.nsIMessenger);
      let msgService = messenger.messageServiceFromURI(uriSpec);

      let url;
      if (isPostbox()) {
        // Postbox
        url = msgService.GetUrlForUri(uriSpec, null);
      }
      else {
        // TB
        let urlObj = {};
        msgService.GetUrlForUri(uriSpec, urlObj, null);

        url = urlObj.value;
      }

      if (url.scheme == "file") {
        return url;
      }
      else {
        return url.QueryInterface(Ci.nsIMsgMailNewsUrl);
      }

    }
    catch (ex) {
      return null;
    }
  },
  /**
   * Copy a file to a mail folder.
   *   in nsIFile aFile,
   *   in nsIMsgFolder dstFolder,
   *   in unsigned long aMsgFlags,
   *   in ACString aMsgKeywords,
   *   in nsIMsgCopyServiceListener listener,
   *   in nsIMsgWindow msgWindow
   */
  copyFileToMailFolder: function(file, destFolder, msgFlags, msgKeywords, listener, msgWindow) {
    let copySvc = Cc["@mozilla.org/messenger/messagecopyservice;1"].getService(Ci.nsIMsgCopyService);

    if (isPostbox()) {
      // Postbox
      return copySvc.CopyFileMessage(file, destFolder, msgFlags, msgKeywords, listener, msgWindow);
    }
    else {
      // TB
      return copySvc.CopyFileMessage(file, destFolder, null, false, msgFlags, msgKeywords, listener, msgWindow);
    }

  }
 };

 function isPostbox() {
  // return true if Postbox, false otherwise

  if (gIsPostbox !== null) return gIsPostbox;

  gIsPostbox = Cc[XPCOM_APPINFO].getService(Ci.nsIXULAppInfo).ID == POSTBOX_ID;
  return gIsPostbox;
}

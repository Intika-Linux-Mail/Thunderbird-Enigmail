/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailPbxCompat"];

const POSTBOX_ID = "postbox@postbox-inc.com";
const XPCOM_APPINFO = "@mozilla.org/xre/app-info;1";

var gIsPostbox = null;

/**
 * Message-reading related functions
 */

var MailUtils;

try {
  // Postbox / TB < 60
  MailUtils = ChromeUtils.import("resource:///modules/MailUtils.js").MailUtils;
}
catch (x) {
  // Thunderbird
  MailUtils = ChromeUtils.import("resource:///modules/MailUtils.jsm").MailUtils;
}

var EnigmailPbxCompat = {

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

  },

  getExistingFolder: function(folderUri) {
    if ("getExistingFolder" in MailUtils) {
      // TB >= 65
      return MailUtils.getExistingFolder(folderUri);
    }
    else {
      return MailUtils.getFolderForURI(folderUri, false);
    }
  }
};


function isPostbox() {
  // return true if Postbox, false otherwise

  if (gIsPostbox !== null) return gIsPostbox;

  gIsPostbox = Cc[XPCOM_APPINFO].getService(Ci.nsIXULAppInfo).ID == POSTBOX_ID;
  return gIsPostbox;
}

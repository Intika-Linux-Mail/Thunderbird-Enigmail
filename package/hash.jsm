/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailHash"];


const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
const EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;


const keyAlgorithms = [];
const mimeHashAlgorithms = [null, "sha1", "ripemd160", "sha256", "sha384", "sha512", "sha224", "md5"];

var EnigmailHash = {
  determineAlgorithm: function(win, fromMailAddr, hashAlgoObj) {
    EnigmailLog.DEBUG("hash.jsm: determineAlgorithm\n");

    if (!win) {
      win = EnigmailWindows.getMostRecentWindow();
    }

    const sendFlags = EnigmailConstants.SEND_TEST | EnigmailConstants.SEND_SIGNED;

    if (typeof(keyAlgorithms[fromMailAddr]) != "string") {
      // hash algorithm not yet known
      const cApi = EnigmailCryptoAPI();
      let ret = null;

      try {
        ret = cApi.sync(cApi.encryptMessage(fromMailAddr,
          "",
          "",
          sendFlags,
          "Test",
          null,
          win));
      }
      catch (ex) {}

      if (! ret) return -2;

      if (!ret.data || ret.data.length === 0) {
        if (ret.exitCode === 0) {
          ret.exitCode = -1;
        }
        if (ret.statusFlags & EnigmailConstants.BAD_PASSPHRASE) {
          ret.errorMsg = EnigmailLocale.getString("badPhrase");
        }
        EnigmailDialog.alert(win, ret.errorMsg);
        return ret.exitCode;
      }

      let hashAlgorithm = "sha256"; // safe default in 2019

      const m = ret.data.match(/^(Hash: )(.*)$/m);
      if (m && (m.length > 2) && (m[1] == "Hash: ")) {
        hashAlgorithm = m[2].toLowerCase();
      }
      else {
        EnigmailLog.DEBUG("hash.jsm: determineAlgorithm: no hashAlgorithm specified - using SHA256\n");
      }

      for (let i = 1; i < mimeHashAlgorithms.length; i++) {
        if (mimeHashAlgorithms[i] === hashAlgorithm) {
          EnigmailLog.DEBUG("hash.jsm: determineAlgorithm: found hashAlgorithm " + hashAlgorithm + "\n");
          keyAlgorithms[fromMailAddr] = hashAlgorithm;
          hashAlgoObj.value = hashAlgorithm;
          return 0;
        }
      }

      EnigmailLog.ERROR("hash.jsm: determineAlgorithm: no hashAlgorithm found\n");
      return 2;
    }
    else {
      EnigmailLog.DEBUG("hash.jsm: determineAlgorithm: hashAlgorithm " + keyAlgorithms[fromMailAddr] + " is cached\n");
      hashAlgoObj.value = keyAlgorithms[fromMailAddr];
    }

    return 0;
  }
};

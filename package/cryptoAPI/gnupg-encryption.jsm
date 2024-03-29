/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["GnuPG_Encryption"];

const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
const EnigmailGpgAgent = ChromeUtils.import("chrome://enigmail/content/modules/gpgAgent.jsm").EnigmailGpgAgent;
const EnigmailGpg = ChromeUtils.import("chrome://enigmail/content/modules/gpg.jsm").EnigmailGpg;
const EnigmailErrorHandling = ChromeUtils.import("chrome://enigmail/content/modules/errorHandling.jsm").EnigmailErrorHandling;
const EnigmailExecution = ChromeUtils.import("chrome://enigmail/content/modules/execution.jsm").EnigmailExecution;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailPassword = ChromeUtils.import("chrome://enigmail/content/modules/passwords.jsm").EnigmailPassword;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;


const gMimeHashAlgorithms = [null, "sha1", "ripemd160", "sha256", "sha384", "sha512", "sha224", "md5"];

const ENC_TYPE_MSG = 0;
const ENC_TYPE_ATTACH_BINARY = 1;
const ENC_TYPE_ATTACH_ASCII = 2;

const GPG_COMMENT_OPT = "Using GnuPG with %s - https://www.enigmail.net/";


var GnuPG_Encryption = {
  encryptMessageStart: function(win, uiFlags, fromMailAddr, toMailAddr, bccMailAddr,
    hashAlgorithm, sendFlags, listener, statusFlagsObj, errorMsgObj) {
    EnigmailLog.DEBUG("encryption.jsm: encryptMessageStart: uiFlags=" + uiFlags + ", from " + fromMailAddr + " to " + toMailAddr + ", hashAlgorithm=" + hashAlgorithm + " (" + EnigmailData.bytesToHex(
      EnigmailData.pack(sendFlags, 4)) + ")\n");

    let keyUseability = determineOwnKeyUsability(sendFlags, fromMailAddr);

    if (!keyUseability.keyId) {
      EnigmailLog.DEBUG("encryption.jsm: encryptMessageStart: own key invalid\n");
      errorMsgObj.value = keyUseability.errorMsg;
      statusFlagsObj.value = EnigmailConstants.INVALID_RECIPIENT | EnigmailConstants.NO_SECKEY | EnigmailConstants.DISPLAY_MESSAGE;

      return null;
    }

    var pgpMime = uiFlags & EnigmailConstants.UI_PGP_MIME;

    var hashAlgo = gMimeHashAlgorithms[EnigmailPrefs.getPref("mimeHashAlgorithm")];

    if (hashAlgorithm) {
      hashAlgo = hashAlgorithm;
    }

    errorMsgObj.value = "";

    if (!sendFlags) {
      EnigmailLog.DEBUG("encryption.jsm: encryptMessageStart: NO ENCRYPTION!\n");
      errorMsgObj.value = EnigmailLocale.getString("notRequired");
      return null;
    }

    if (!EnigmailCore.getService(win)) {
      EnigmailLog.ERROR("encryption.jsm: encryptMessageStart: not yet initialized\n");
      errorMsgObj.value = EnigmailLocale.getString("notInit");
      return null;
    }

    let logFileObj = {};
    let encryptArgs = getEncryptCommand(fromMailAddr, toMailAddr, bccMailAddr, hashAlgo, sendFlags, ENC_TYPE_MSG, errorMsgObj, logFileObj);
    if (!encryptArgs)
      return null;

    var signMsg = sendFlags & EnigmailConstants.SEND_SIGNED;
    if (!listener) {
      listener = {};
    }
    if ("done" in listener) {
      listener.outerDone = listener.done;
    }

    listener.done = function(exitCode) {
      EnigmailErrorHandling.appendLogFileToDebug(logFileObj.value);
      if (this.outerDone) {
        this.outerDone(exitCode);
      }
    };

    var proc = EnigmailExecution.execStart(EnigmailGpgAgent.agentPath, encryptArgs, signMsg, win, listener, statusFlagsObj);

    if (statusFlagsObj.value & EnigmailConstants.MISSING_PASSPHRASE) {
      EnigmailLog.ERROR("encryption.jsm: encryptMessageStart: Error - no passphrase supplied\n");

      errorMsgObj.value = "";
    }

    if (pgpMime && errorMsgObj.value) {
      EnigmailDialog.alert(win, errorMsgObj.value);
    }

    return proc;
  },

  encryptMessageEnd: function(fromMailAddr, stderrStr, exitCode, uiFlags, sendFlags, outputLen, retStatusObj) {
    EnigmailLog.DEBUG("encryption.jsm: encryptMessageEnd: uiFlags=" + uiFlags + ", sendFlags=" + EnigmailData.bytesToHex(EnigmailData.pack(sendFlags, 4)) + ", outputLen=" + outputLen + "\n");

    var pgpMime = uiFlags & EnigmailConstants.UI_PGP_MIME;
    var defaultSend = sendFlags & EnigmailConstants.SEND_DEFAULT;
    var signMsg = sendFlags & EnigmailConstants.SEND_SIGNED;
    var encryptMsg = sendFlags & EnigmailConstants.SEND_ENCRYPTED;

    retStatusObj.statusFlags = 0;
    retStatusObj.errorMsg = "";
    retStatusObj.blockSeparation = "";

    if (!EnigmailCore.getService().initialized) {
      EnigmailLog.ERROR("encryption.jsm: encryptMessageEnd: not yet initialized\n");
      retStatusObj.errorMsg = EnigmailLocale.getString("notInit");
      return -1;
    }

    EnigmailErrorHandling.parseErrorOutput(stderrStr, retStatusObj);

    exitCode = EnigmailExecution.fixExitCode(exitCode, retStatusObj);
    if ((exitCode === 0) && !outputLen) {
      exitCode = -1;
    }

    if (exitCode !== 0 && (signMsg || encryptMsg)) {
      // GnuPG might return a non-zero exit code, even though the message was correctly
      // signed or encryped -> try to fix the exit code

      var correctedExitCode = 0;
      if (signMsg) {
        if (!(retStatusObj.statusFlags & EnigmailConstants.SIG_CREATED)) correctedExitCode = exitCode;
      }
      if (encryptMsg) {
        if (!(retStatusObj.statusFlags & EnigmailConstants.END_ENCRYPTION)) correctedExitCode = exitCode;
      }
      exitCode = correctedExitCode;
    }

    EnigmailLog.DEBUG("encryption.jsm: encryptMessageEnd: command execution exit code: " + exitCode + "\n");

    if (retStatusObj.statusFlags & EnigmailConstants.DISPLAY_MESSAGE) {
      if (retStatusObj.extendedStatus.search(/\bdisp:/) >= 0) {
        retStatusObj.errorMsg = retStatusObj.statusMsg;
      }
      else {
        if (fromMailAddr.search(/^0x/) === 0) {
          fromMailAddr = fromMailAddr.substr(2);
        }
        if (fromMailAddr.search(/^[A-F0-9]{8,40}$/i) === 0) {
          fromMailAddr = "[A-F0-9]+" + fromMailAddr;
        }

        let s = new RegExp("^(\\[GNUPG:\\] )?INV_(RECP|SGNR) [0-9]+ (\\<|0x)?" + fromMailAddr + "\\>?", "m");
        if (retStatusObj.statusMsg.search(s) >= 0) {
          retStatusObj.errorMsg += "\n\n" + EnigmailLocale.getString("keyError.resolutionAction");
        }
        else if (retStatusObj.statusMsg.length > 0) {
          retStatusObj.errorMsg = retStatusObj.statusMsg;
        }
      }
    }
    else if (retStatusObj.statusFlags & EnigmailConstants.INVALID_RECIPIENT) {
      retStatusObj.errorMsg = retStatusObj.statusMsg;
    }
    else if (exitCode !== 0) {
      retStatusObj.errorMsg = EnigmailLocale.getString("badCommand");
    }

    return exitCode;
  },

  encryptMessage: function(parent, uiFlags, plainText, fromMailAddr, toMailAddr, bccMailAddr, sendFlags,
    exitCodeObj, statusFlagsObj, errorMsgObj) {
    EnigmailLog.DEBUG("enigmail.js: Enigmail.encryptMessage: " + plainText.length + " bytes from " + fromMailAddr + " to " + toMailAddr + " (" + sendFlags + ")\n");

    exitCodeObj.value = -1;
    statusFlagsObj.value = 0;
    errorMsgObj.value = "";

    if (!plainText) {
      EnigmailLog.DEBUG("enigmail.js: Enigmail.encryptMessage: NO ENCRYPTION!\n");
      exitCodeObj.value = 0;
      EnigmailLog.DEBUG("  <=== encryptMessage()\n");
      return plainText;
    }

    var defaultSend = sendFlags & EnigmailConstants.SEND_DEFAULT;
    var signMsg = sendFlags & EnigmailConstants.SEND_SIGNED;
    var encryptMsg = sendFlags & EnigmailConstants.SEND_ENCRYPTED;

    if (encryptMsg) {
      // First convert all linebreaks to newlines
      plainText = plainText.replace(/\r\n/g, "\n");
      plainText = plainText.replace(/\r/g, "\n");

      // we need all data in CRLF according to RFC 4880
      plainText = plainText.replace(/\n/g, "\r\n");
    }

    var listener = EnigmailExecution.newSimpleListener(
      function _stdin(pipe) {
        pipe.write(plainText);
        pipe.close();
      },
      function _done(exitCode) {});


    var proc = GnuPG_Encryption.encryptMessageStart(parent, uiFlags,
      fromMailAddr, toMailAddr, bccMailAddr,
      null, sendFlags,
      listener, statusFlagsObj, errorMsgObj);
    if (!proc) {
      exitCodeObj.value = -1;
      EnigmailLog.DEBUG("  <=== encryptMessage()\n");
      return "";
    }

    // Wait for child pipes to close
    proc.wait();

    var retStatusObj = {};
    exitCodeObj.value = GnuPG_Encryption.encryptMessageEnd(fromMailAddr, EnigmailData.getUnicodeData(listener.stderrData), listener.exitCode,
      uiFlags, sendFlags,
      listener.stdoutData.length,
      retStatusObj);

    statusFlagsObj.value = retStatusObj.statusFlags;
    statusFlagsObj.statusMsg = retStatusObj.statusMsg;
    errorMsgObj.value = retStatusObj.errorMsg;


    if ((exitCodeObj.value === 0) && listener.stdoutData.length === 0)
      exitCodeObj.value = -1;

    if (exitCodeObj.value === 0) {
      // Normal return
      EnigmailLog.DEBUG("  <=== encryptMessage()\n");
      return EnigmailData.getUnicodeData(listener.stdoutData);
    }

    // Error processing
    EnigmailLog.DEBUG("enigmail.js: Enigmail.encryptMessage: command execution exit code: " + exitCodeObj.value + "\n");
    return "";
  },

  encryptAttachment: function(parent, fromMailAddr, toMailAddr, bccMailAddr, sendFlags, inFile, outFile,
    exitCodeObj, statusFlagsObj, errorMsgObj) {
    EnigmailLog.DEBUG("encryption.jsm: GnuPG_Encryption.encryptAttachment infileName=" + inFile.path + "\n");

    statusFlagsObj.value = 0;
    sendFlags |= EnigmailConstants.SEND_ATTACHMENT;

    let asciiArmor = false;
    try {
      asciiArmor = EnigmailPrefs.getPrefBranch().getBoolPref("inlineAttachAsciiArmor");
    }
    catch (ex) {}

    const asciiFlags = (asciiArmor ? ENC_TYPE_ATTACH_ASCII : ENC_TYPE_ATTACH_BINARY);
    let args = getEncryptCommand(fromMailAddr, toMailAddr, bccMailAddr, "", sendFlags, asciiFlags, errorMsgObj);

    if (!args) {
      return null;
    }

    const signMessage = (sendFlags & EnigmailConstants.SEND_SIGNED);

    if (signMessage) {
      args = args.concat(EnigmailPassword.command());
    }

    //const inFilePath = EnigmailFiles.getEscapedFilename(EnigmailFiles.getFilePathReadonly(inFile.QueryInterface(Ci.nsIFile)));
    const fileContents = EnigmailFiles.readBinaryFile(inFile.QueryInterface(Ci.nsIFile));
    const inFileName = inFile.QueryInterface(Ci.nsIFile).leafName;
    const outFilePath = EnigmailFiles.getEscapedFilename(EnigmailFiles.getFilePathReadonly(outFile.QueryInterface(Ci.nsIFile)));

    args = args.concat(["--yes", "-o", outFilePath, "--set-filename", inFileName]);

    let cmdErrorMsgObj = {};

    const msg = EnigmailExecution.execCmd(EnigmailGpgAgent.agentPath, args, fileContents, exitCodeObj, statusFlagsObj, {}, cmdErrorMsgObj);
    if (exitCodeObj.value !== 0) {
      if (cmdErrorMsgObj.value) {
        errorMsgObj.value = EnigmailFiles.formatCmdLine(EnigmailGpgAgent.agentPath, args);
        errorMsgObj.value += "\n" + cmdErrorMsgObj.value;
      }
      else {
        errorMsgObj.value = "An unknown error has occurred";
      }

      return "";
    }

    return msg;
  }
};


function getEncryptCommand(fromMailAddr, toMailAddr, bccMailAddr, hashAlgorithm, sendFlags, isAscii, errorMsgObj,
  logFileObj) {
  EnigmailLog.DEBUG("encryption.jsm: getEncryptCommand: hashAlgorithm=" + hashAlgorithm + "\n");

  try {
    fromMailAddr = EnigmailFuncs.stripEmail(fromMailAddr);
    toMailAddr = EnigmailFuncs.stripEmail(toMailAddr);
    bccMailAddr = EnigmailFuncs.stripEmail(bccMailAddr);

  }
  catch (ex) {
    errorMsgObj.value = EnigmailLocale.getString("invalidEmail");
    return null;
  }

  var signMsg = sendFlags & EnigmailConstants.SEND_SIGNED;
  var encryptMsg = sendFlags & EnigmailConstants.SEND_ENCRYPTED;
  var usePgpMime = sendFlags & EnigmailConstants.SEND_PGP_MIME;

  var useDefaultComment = false;
  try {
    useDefaultComment = EnigmailPrefs.getPref("useDefaultComment");
  }
  catch (ex) {}

  var hushMailSupport = false;
  try {
    hushMailSupport = EnigmailPrefs.getPref("hushMailSupport");
  }
  catch (ex) {}

  var detachedSig = (usePgpMime || (sendFlags & EnigmailConstants.SEND_ATTACHMENT)) && signMsg && !encryptMsg;

  var toAddrList = toMailAddr.split(/\s*,\s*/);
  var bccAddrList = bccMailAddr.split(/\s*,\s*/);
  var k;

  var encryptArgs = EnigmailGpg.getStandardArgs(true);

  if (!useDefaultComment)
    encryptArgs = encryptArgs.concat(["--comment", GPG_COMMENT_OPT.replace(/%s/, EnigmailApp.getName())]);

  var angledFromMailAddr = ((fromMailAddr.search(/^0x/) === 0) || hushMailSupport) ?
    fromMailAddr : "<" + fromMailAddr + ">";
  angledFromMailAddr = angledFromMailAddr.replace(/(["'`])/g, "\\$1");

  if (signMsg && hashAlgorithm) {
    encryptArgs = encryptArgs.concat(["--digest-algo", hashAlgorithm]);
  }

  if (logFileObj) {
    logFileObj.value = EnigmailErrorHandling.getTempLogFile();
    encryptArgs.push("--log-file");
    encryptArgs.push(EnigmailFiles.getEscapedFilename(EnigmailFiles.getFilePath(logFileObj.value)));
  }

  if (encryptMsg) {
    switch (isAscii) {
      case ENC_TYPE_MSG:
        encryptArgs.push("-a");
        encryptArgs.push("-t");
        break;
      case ENC_TYPE_ATTACH_ASCII:
        encryptArgs.push("-a");
    }

    encryptArgs.push("--encrypt");

    if (signMsg)
      encryptArgs.push("--sign");

    if (sendFlags & EnigmailConstants.SEND_ALWAYS_TRUST) {
      encryptArgs.push("--trust-model");
      encryptArgs.push("always");
    }
    if ((sendFlags & EnigmailConstants.SEND_ENCRYPT_TO_SELF) && fromMailAddr)
      encryptArgs = encryptArgs.concat(["--encrypt-to", angledFromMailAddr]);

    for (k = 0; k < toAddrList.length; k++) {
      toAddrList[k] = toAddrList[k].replace(/'/g, "\\'");
      if (toAddrList[k].length > 0) {
        encryptArgs.push("-r");
        if (toAddrList[k].search(/^GROUP:/) === 0) {
          // groups from gpg.conf file
          encryptArgs.push(toAddrList[k].substr(6));
        }
        else {
          encryptArgs.push((hushMailSupport || (toAddrList[k].search(/^0x/) === 0)) ? toAddrList[k] : "<" + toAddrList[k] + ">");
        }
      }
    }

    for (k = 0; k < bccAddrList.length; k++) {
      bccAddrList[k] = bccAddrList[k].replace(/'/g, "\\'");
      if (bccAddrList[k].length > 0) {
        encryptArgs.push("--hidden-recipient");
        encryptArgs.push((hushMailSupport || (bccAddrList[k].search(/^0x/) === 0)) ? bccAddrList[k] : "<" + bccAddrList[k] + ">");
      }
    }

  }
  else if (detachedSig) {
    encryptArgs = encryptArgs.concat(["-s", "-b"]);

    switch (isAscii) {
      case ENC_TYPE_MSG:
        encryptArgs = encryptArgs.concat(["-a", "-t"]);
        break;
      case ENC_TYPE_ATTACH_ASCII:
        encryptArgs.push("-a");
    }

  }
  else if (signMsg) {
    encryptArgs = encryptArgs.concat(["-t", "--clearsign"]);
  }

  if (fromMailAddr) {
    encryptArgs = encryptArgs.concat(["-u", angledFromMailAddr]);
  }

  return encryptArgs;
}


/**
 * Determine if the sender key ID or user ID can be used for signing and/or encryption
 *
 * @param sendFlags:    Number  - the send Flags; need to contain SEND_SIGNED and/or SEND_ENCRYPTED
 * @param fromMailAddr: String  - the sender email address or key ID
 *
 * @return Object:
 *         - keyId:    String - the found key ID, or null if fromMailAddr is not valid
 *         - errorMsg: String - the erorr message if key not valid, or null if key is valid
 */
function determineOwnKeyUsability(sendFlags, fromMailAddr) {
  EnigmailLog.DEBUG("encryption.jsm: determineOwnKeyUsability: sendFlags=" + sendFlags + ", sender=" + fromMailAddr + "\n");

  let keyList = [];
  let ret = {
    keyId: null,
    errorMsg: null
  };

  let sign = (sendFlags & EnigmailConstants.SEND_SIGNED ? true : false);
  let encrypt = (sendFlags & EnigmailConstants.SEND_ENCRYPTED ? true : false);

  if (fromMailAddr.search(/^(0x)?[A-Z0-9]+$/) === 0) {
    // key ID specified
    let key = EnigmailKeyRing.getKeyById(fromMailAddr);
    keyList.push(key);
  }
  else {
    // email address specified
    keyList = EnigmailKeyRing.getKeysByUserId(fromMailAddr);
  }

  if (keyList.length === 0) {
    ret.errorMsg = EnigmailLocale.getString("errorOwnKeyUnusable", fromMailAddr);
    return ret;
  }

  if (sign) {
    keyList = keyList.reduce(function _f(p, keyObj) {
      if (keyObj && keyObj.getSigningValidity().keyValid) p.push(keyObj);
      return p;
    }, []);
  }

  if (encrypt) {
    keyList = keyList.reduce(function _f(p, keyObj) {
      if (keyObj && keyObj.getEncryptionValidity().keyValid) p.push(keyObj);
      return p;
    }, []);
  }

  if (keyList.length === 0) {
    if (sign) {
      ret.errorMsg = EnigmailErrorHandling.determineInvSignReason(fromMailAddr);
    }
    else {
      ret.errorMsg = EnigmailErrorHandling.determineInvRcptReason(fromMailAddr);
    }
  }
  else {
    ret.keyId = keyList[0].fpr;
  }

  return ret;
}

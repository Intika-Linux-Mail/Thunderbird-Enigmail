/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailMimeDecrypt"];

/**
 *  Module for handling PGP/MIME encrypted messages
 *  implemented as an XPCOM object
 */

const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailVerify = ChromeUtils.import("chrome://enigmail/content/modules/mimeVerify.jsm").EnigmailVerify;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailDecryption = ChromeUtils.import("chrome://enigmail/content/modules/decryption.jsm").EnigmailDecryption;
var EnigmailMime = ChromeUtils.import("chrome://enigmail/content/modules/mime.jsm").EnigmailMime;
const EnigmailURIs = ChromeUtils.import("chrome://enigmail/content/modules/uris.jsm").EnigmailURIs;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const EnigmailSingletons = ChromeUtils.import("chrome://enigmail/content/modules/singletons.jsm").EnigmailSingletons;
const EnigmailHttpProxy = ChromeUtils.import("chrome://enigmail/content/modules/httpProxy.jsm").EnigmailHttpProxy;
const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
const EnigmailAutocrypt = ChromeUtils.import("chrome://enigmail/content/modules/autocrypt.jsm").EnigmailAutocrypt;
const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;

const getKeyRing = EnigmailLazy.loader("enigmail/keyRing.jsm", "EnigmailKeyRing");


const APPSHELL_MEDIATOR_CONTRACTID = "@mozilla.org/appshell/window-mediator;1";
const PGPMIME_JS_DECRYPTOR_CONTRACTID = "@mozilla.org/mime/pgp-mime-js-decrypt;1";
const PGPMIME_JS_DECRYPTOR_CID = Components.ID("{7514cbeb-2bfd-4b2c-829b-1a4691fa0ac8}");

const ENCODING_DEFAULT = 0;
const ENCODING_BASE64 = 1;
const ENCODING_QP = 2;

const LAST_MSG = EnigmailSingletons.lastDecryptedMessage;

var gDebugLogLevel = 0;

var gNumProc = 0;

var EnigmailMimeDecrypt = {
  /**
   * create a new instance of a PGP/MIME decryption handler
   */
  newPgpMimeHandler: function() {
    return new MimeDecryptHandler();
  },

  /**
   * Return a fake empty attachment with information that the message
   * was not decrypted
   *
   * @return {String}: MIME string (HTML text)
   */
  emptyAttachment: function() {
    EnigmailLog.DEBUG("mimeDecrypt.jsm: emptyAttachment()\n");

    let encPart = EnigmailLocale.getString("mimeDecrypt.encryptedPart.attachmentLabel");
    let concealed = EnigmailLocale.getString("mimeDecrypt.encryptedPart.concealedData");
    let retData =
      `Content-Type: message/rfc822; name="${encPart}.eml"
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="${encPart}.eml"

Content-Type: text/html

<p><i>${concealed}</i></p>
`;
    return retData;
  },

  /**
   * Wrap the decrypted output into a message/rfc822 attachment
   *
   * @param {String} decryptingMimePartNum: requested MIME part number
   * @param {Object} uri: nsIURI object of the decrypted message
   *
   * @return {String}: prefix for message data
   */
  pretendAttachment: function(decryptingMimePartNum, uri) {
    if (decryptingMimePartNum === "1" || !uri) return "";

    let msg = "";
    let mimePartNumber = EnigmailMime.getMimePartNumber(uri.spec);

    if (mimePartNumber === decryptingMimePartNum + ".1") {
      msg = 'Content-Type: message/rfc822; name="attachment.eml"\r\n' +
        'Content-Transfer-Encoding: 7bit\r\n' +
        'Content-Disposition: attachment; filename="attachment.eml"\r\n\r\n';

      try {
        let dbHdr = uri.QueryInterface(Ci.nsIMsgMessageUrl).messageHeader;
        if (dbHdr.subject) msg += `Subject: ${dbHdr.subject}\r\n`;
        if (dbHdr.author) msg += `From: ${dbHdr.author}\r\n`;
        if (dbHdr.recipients) msg += `To: ${dbHdr.recipients}\r\n`;
        if (dbHdr.ccList) msg += `Cc: ${dbHdr.ccList}\r\n`;
      } catch (x) {}
    }

    return msg;
  }
};

////////////////////////////////////////////////////////////////////
// handler for PGP/MIME encrypted messages
// data is processed from libmime -> nsPgpMimeProxy

function MimeDecryptHandler() {

  EnigmailLog.DEBUG("mimeDecrypt.jsm: MimeDecryptHandler()\n"); // always log this one
  this.mimeSvc = null;
  this.initOk = false;
  this.boundary = "";
  this.pipe = null;
  this.closePipe = false;
  this.statusStr = "";
  this.outQueue = "";
  this.dataLength = 0;
  this.bytesWritten = 0;
  this.mimePartCount = 0;
  this.headerMode = 0;
  this.xferEncoding = ENCODING_DEFAULT;
  this.matchedPgpDelimiter = 0;
  this.exitCode = null;
  this.msgWindow = null;
  this.msgUriSpec = null;
  this.returnStatus = null;
  this.proc = null;
  this.statusDisplayed = false;
  this.uri = null;
  this.backgroundJob = false;
  this.decryptedHeaders = {};
  this.mimePartNumber = "";
  this.dataIsBase64 = null;
  this.base64Cache = "";

  if (EnigmailCompat.isMessageUriInPgpMime()) {
    this.onDataAvailable = this.onDataAvailable68;
  } else {
    this.onDataAvailable = this.onDataAvailable60;
  }
}

MimeDecryptHandler.prototype = {
  inStream: Cc["@mozilla.org/scriptableinputstream;1"].createInstance(Ci.nsIScriptableInputStream),

  onStartRequest: function(request, uri) {
    if (!EnigmailCore.getService()) // Ensure Enigmail is initialized
      return;
    EnigmailLog.DEBUG("mimeDecrypt.jsm: onStartRequest\n"); // always log this one

    ++gNumProc;
    if (gNumProc > EnigmailPrefs.getPref("maxNumProcesses")) {
      EnigmailLog.DEBUG("mimeDecrypt.jsm: number of parallel requests above threshold - ignoring requst\n");
      return;
    }

    this.initOk = true;
    this.mimeSvc = request.QueryInterface(Ci.nsIPgpMimeProxy);
    if ("mimePart" in this.mimeSvc) {
      this.mimePartNumber = this.mimeSvc.mimePart;
    } else {
      this.mimePartNumber = "";
    }

    if ("messageURI" in this.mimeSvc) {
      this.uri = this.mimeSvc.messageURI;
      if (this.uri) {
        EnigmailLog.DEBUG("mimeDecrypt.jsm: onStartRequest: uri='" + this.uri.spec + "'\n");
      }
      else {
        EnigmailLog.DEBUG("mimeDecrypt.jsm: onStartRequest: uri=null\n");
      }
    } else {
      if (uri) {
        this.uri = uri.QueryInterface(Ci.nsIURI);
        EnigmailLog.DEBUG("mimeDecrypt.jsm: onStartRequest: uri='" + this.uri.spec + "'\n");
      }
    }
    this.pipe = null;
    this.closePipe = false;
    this.exitCode = null;
    this.msgWindow = EnigmailVerify.lastMsgWindow;
    this.msgUriSpec = EnigmailVerify.lastMsgUri;

    this.statusDisplayed = false;
    this.returnStatus = null;
    this.dataLength = 0;
    this.decryptedData = "";
    this.mimePartCount = 0;
    this.bytesWritten = 0;
    this.matchedPgpDelimiter = 0;
    this.dataIsBase64 = null;
    this.base64Cache = "";
    this.outQueue = "";
    this.statusStr = "";
    this.headerMode = 0;
    this.decryptedHeaders = {};
    this.xferEncoding = ENCODING_DEFAULT;
    this.boundary = EnigmailMime.getBoundary(this.mimeSvc.contentType);

    if (!this.isReloadingLastMessage()) {
      EnigmailSingletons.clearLastDecryptedMessage();
    }
  },

  processData: function(data) {
    // detect MIME part boundary
    if (data.indexOf(this.boundary) >= 0) {
      LOCAL_DEBUG("mimeDecrypt.jsm: processData: found boundary\n");
      ++this.mimePartCount;
      this.headerMode = 1;
      return;
    }

    // found PGP/MIME "body"
    if (this.mimePartCount == 2) {

      if (this.headerMode == 1) {
        // we are in PGP/MIME main part headers
        if (data.search(/\r|\n/) === 0) {
          // end of Mime-part headers reached
          this.headerMode = 2;
          return;
        } else {
          if (data.search(/^content-transfer-encoding:\s*/i) >= 0) {
            // extract content-transfer-encoding
            data = data.replace(/^content-transfer-encoding:\s*/i, "");
            data = data.replace(/;.*/, "").toLowerCase().trim();
            if (data.search(/base64/i) >= 0) {
              this.xferEncoding = ENCODING_BASE64;
            } else if (data.search(/quoted-printable/i) >= 0) {
              this.xferEncoding = ENCODING_QP;
            }

          }
        }
      } else {
        // PGP/MIME main part body
        if (this.xferEncoding == ENCODING_QP) {
          this.cacheData(EnigmailData.decodeQuotedPrintable(data));
        } else {
          this.cacheData(data);
        }
      }
    }
  },

  /**
   * onDataAvailable for TB <= 66
   */
  onDataAvailable60: function(req, dummy, stream, offset, count) {

    // get data from libmime
    if (!this.initOk) return;
    this.inStream.init(stream);

    if (count > 0) {
      var data = this.inStream.read(count);

      if (this.mimePartCount == 0 && this.dataIsBase64 === null) {
        // try to determine if this could be a base64 encoded message part
        this.dataIsBase64 = this.isBase64Encoding(data);
      }

      if (!this.dataIsBase64) {
        if (data.search(/[\r\n][^\r\n]+[\r\n]/) >= 0) {
          // process multi-line data line by line
          let lines = data.replace(/\r\n/g, "\n").split(/\n/);

          for (let i = 0; i < lines.length; i++) {
            this.processData(lines[i] + "\r\n");
          }
        } else
          this.processData(data);
      } else {
        this.base64Cache += data;
      }
    }
  },

  /**
   * onDataAvailable for TB >= 68
   */
  onDataAvailable68: function(req, stream, offset, count) {

    // get data from libmime
    if (!this.initOk) return;
    this.inStream.init(stream);

    if (count > 0) {
      var data = this.inStream.read(count);

      if (this.mimePartCount == 0 && this.dataIsBase64 === null) {
        // try to determine if this could be a base64 encoded message part
        this.dataIsBase64 = this.isBase64Encoding(data);
      }

      if (!this.dataIsBase64) {
        if (data.search(/[\r\n][^\r\n]+[\r\n]/) >= 0) {
          // process multi-line data line by line
          let lines = data.replace(/\r\n/g, "\n").split(/\n/);

          for (let i = 0; i < lines.length; i++) {
            this.processData(lines[i] + "\r\n");
          }
        } else
          this.processData(data);
      } else {
        this.base64Cache += data;
      }
    }
  },

  /**
   * Try to determine if data is base64 endoded
   */
  isBase64Encoding: function(str) {
    let ret = false;

    str = str.replace(/[\r\n]/, "");
    if (str.search(/^[A-Za-z0-9+/=]+$/) === 0) {
      let excess = str.length % 4;
      str = str.substring(0, str.length - excess);

      try {
        let s = atob(str);
        // if the conversion succeds, we have a base64 encoded message
        ret = true;
      } catch (ex) {
        // not a base64 encoded
      }
    }

    return ret;
  },

  // cache encrypted data for writing to subprocess
  cacheData: function(str) {
    if (gDebugLogLevel > 4)
      LOCAL_DEBUG("mimeDecrypt.jsm: cacheData: " + str.length + "\n");

    this.outQueue += str;
  },

  processBase64Message: function() {
    LOCAL_DEBUG("mimeDecrypt.jsm: processBase64Message\n");

    try {
      this.base64Cache = EnigmailData.decodeBase64(this.base64Cache);
    } catch (ex) {
      // if decoding failed, try non-encoded version
    }

    let lines = this.base64Cache.replace(/\r\n/g, "\n").split(/\n/);

    for (let i = 0; i < lines.length; i++) {
      this.processData(lines[i] + "\r\n");
    }
  },

  /**
   * Determine if we are reloading the same message as the previous one
   *
   * @return Boolean
   */
  isReloadingLastMessage: function() {
    if (!this.uri) return false;
    if (!LAST_MSG.lastMessageURI) return false;
    if (("lastMessageData" in LAST_MSG) && LAST_MSG.lastMessageData === "") return false;
    if (this.isUrlEnigmailConvert()) return false;

    let currMsg = EnigmailURIs.msgIdentificationFromUrl(this.uri);

    if (LAST_MSG.lastMessageURI.folder === currMsg.folder && LAST_MSG.lastMessageURI.msgNum === currMsg.msgNum) {
      return true;
    }

    return false;
  },

  isUrlEnigmailConvert: function() {
    if (!this.uri) return false;

    return (this.uri.spec.search(/[&?]header=enigmailConvert/) >= 0);
  },

  onStopRequest: function(request, status, dummy) {
    LOCAL_DEBUG("mimeDecrypt.jsm: onStopRequest\n");
    --gNumProc;
    if (!this.initOk) return;

    if (this.dataIsBase64) {
      this.processBase64Message();
    }

    // ensure that all keys are loaded before processing the message
    getKeyRing().getAllKeys();

    this.msgWindow = EnigmailVerify.lastMsgWindow;
    this.msgUriSpec = EnigmailVerify.lastMsgUri;

    let url = {};
    let currMsg = EnigmailURIs.msgIdentificationFromUrl(this.uri);

    this.backgroundJob = false;

    if (this.uri) {
      // return if not decrypting currently displayed message (except if
      // printing, replying, etc)

      this.backgroundJob = (this.uri.spec.search(/[&?]header=(print|quotebody|enigmailConvert)/) >= 0);

      try {
        var messenger = Cc["@mozilla.org/messenger;1"].getService(Ci.nsIMessenger);

        if (!EnigmailPrefs.getPref("autoDecrypt")) {
          // "decrypt manually" mode
          let manUrl = {};

          if (EnigmailVerify.getManualUri()) {
            manUrl.value = EnigmailCompat.getUrlFromUriSpec(EnigmailVerify.getManualUri());
          } else {
            manUrl.value = {
              spec: "enigmail://invalid/message"
            };
          }

          // print a message if not message explicitly decrypted
          let currUrlSpec = this.uri.spec.replace(/(\?.*)(number=[0-9]*)(&.*)?$/, "?$2");
          let manUrlSpec = manUrl.value.spec.replace(/(\?.*)(number=[0-9]*)(&.*)?$/, "?$2");


          if ((!this.backgroundJob) && currUrlSpec.indexOf(manUrlSpec) !== 0) {
            this.handleManualDecrypt();
            return;
          }
        }

        if (this.msgUriSpec) {
          url.value = EnigmailCompat.getUrlFromUriSpec(this.msgUriSpec);
        }

        if (this.uri.spec.search(/[&?]header=[^&]+/) > 0 &&
          this.uri.spec.search(/[&?]examineEncryptedParts=true/) < 0) {

          if (this.uri.spec.search(/[&?]header=(filter|enigmailFilter)(&.*)?$/) > 0) {
            EnigmailLog.DEBUG("mimeDecrypt.jsm: onStopRequest: detected incoming message processing\n");
            return;
          }
        }

        if (this.uri.spec.search(/[&?]header=[^&]+/) < 0 &&
          this.uri.spec.search(/[&?]part=[.0-9]+/) < 0 &&
          this.uri.spec.search(/[&?]examineEncryptedParts=true/) < 0) {

          if (this.uri && url && url.value) {

            if ("path" in url) {
              // TB < 57
              if (url.value.host !== this.uri.host ||
                url.value.path !== this.uri.path)
                return;
            } else {
              // TB >= 57
              if (url.value.host !== this.uri.host ||
                url.value.pathQueryRef !== this.uri.pathQueryRef)
                return;
            }
          }
        }
      } catch (ex) {
        EnigmailLog.writeException("mimeDecrypt.js", ex);
        EnigmailLog.DEBUG("mimeDecrypt.jsm: error while processing " + this.msgUriSpec + "\n");
      }
    }

    let spec = this.uri ? this.uri.spec : null;
    EnigmailLog.DEBUG(`mimeDecrypt.jsm: checking MIME structure for ${this.mimePartNumber} / ${spec}\n`);

    if (!EnigmailMime.isRegularMimeStructure(this.mimePartNumber, spec, false)) {
      if (!this.isUrlEnigmailConvert()) {
        this.returnData(EnigmailMimeDecrypt.emptyAttachment());
      } else {
        throw "mimeDecrypt.jsm: Cannot decrypt messages with mixed (encrypted/non-encrypted) content";
      }
      return;
    }

    if (!this.isReloadingLastMessage()) {
      if (this.xferEncoding == ENCODING_BASE64) {
        this.outQueue = EnigmailData.decodeBase64(this.outQueue) + "\n";
      }

      let win = this.msgWindow;

      if (!EnigmailDecryption.isReady(win)) return;

      // limit output to 100 times message size to avoid DoS attack
      let maxOutput = this.outQueue.length * 100;
      let statusFlagsObj = {};
      let errorMsgObj = {};
      let listener = this;

      EnigmailLog.DEBUG("mimeDecryp.jsm: starting decryption\n");

      let keyserver = EnigmailPrefs.getPref("autoKeyRetrieve");
      let options = {
        keyserver: keyserver,
        keyserverProxy: EnigmailHttpProxy.getHttpProxy(keyserver),
        fromAddr: EnigmailDecryption.getFromAddr(win),
        maxOutputLength: maxOutput
      };
      const cApi = EnigmailCryptoAPI();
      this.returnStatus = cApi.sync(cApi.decryptMime(this.outQueue, options));
      if (!this.returnStatus) {
        this.returnStatus = {
          decryptedData: "",
          exitCode: -1,
          statusFlags: EnigmailConstants.DECRYPTION_FAILED
        };
      }
      this.decryptedData = this.returnStatus.decryptedData;
      this.handleResult(this.returnStatus.exitCode);

      let mdcError = ((this.returnStatus.statusFlags & EnigmailConstants.DECRYPTION_FAILED) ||
        !(this.returnStatus.statusFlags & EnigmailConstants.DECRYPTION_OKAY));

      if (!this.isUrlEnigmailConvert()) {
        // don't return decrypted data if decryption failed (because it's likely an MDC error),
        // unless we are called for permanent decryption
        if (mdcError) {
          this.decryptedData = "";
        }
      }

      this.displayStatus();

      // HACK: remove filename from 1st HTML and plaintext parts to make TB display message without attachment
      this.decryptedData = this.decryptedData.replace(/^Content-Disposition: inline; filename="msg.txt"/m, "Content-Disposition: inline");
      this.decryptedData = this.decryptedData.replace(/^Content-Disposition: inline; filename="msg.html"/m, "Content-Disposition: inline");

      let prefix = EnigmailMimeDecrypt.pretendAttachment(this.mimePartNumber, this.uri);
      this.returnData(prefix + this.decryptedData);

      // don't remember the last message if it contains an embedded PGP/MIME message
      // to avoid ending up in a loop
      if (this.mimePartNumber === "1" &&
        this.decryptedData.search(/^Content-Type:[\t ]+multipart\/encrypted/mi) < 0 &&
        !mdcError) {
        LAST_MSG.lastMessageData = this.decryptedData;
        LAST_MSG.lastMessageURI = currMsg;
        LAST_MSG.lastStatus = this.returnStatus;
        LAST_MSG.lastStatus.decryptedHeaders = this.decryptedHeaders;
        LAST_MSG.lastStatus.mimePartNumber = this.mimePartNumber;
      } else {
        LAST_MSG.lastMessageURI = null;
        LAST_MSG.lastMessageData = "";
      }

      this.decryptedData = "";
      EnigmailLog.DEBUG("mimeDecrypt.jsm: onStopRequest: process terminated\n"); // always log this one
      this.proc = null;
    } else {
      this.returnStatus = LAST_MSG.lastStatus;
      this.decryptedHeaders = LAST_MSG.lastStatus.decryptedHeaders;
      this.mimePartNumber = LAST_MSG.lastStatus.mimePartNumber;
      this.exitCode = 0;
      this.displayStatus();
      this.returnData(LAST_MSG.lastMessageData);
    }
  },

  displayStatus: function() {
    EnigmailLog.DEBUG("mimeDecrypt.jsm: displayStatus()\n");

    if (this.exitCode === null || this.msgWindow === null || this.statusDisplayed) {
      EnigmailLog.DEBUG("mimeDecrypt.jsm: displayStatus: nothing to display\n");
      return;
    }

    let uriSpec = (this.uri ? this.uri.spec : null);

    try {
      EnigmailLog.DEBUG("mimeDecrypt.jsm: displayStatus for uri " + uriSpec + "\n");
      let headerSink = EnigmailSingletons.messageReader;

      if (headerSink && this.uri && !this.backgroundJob) {

        headerSink.processDecryptionResult(this.uri, "modifyMessageHeaders", JSON.stringify(this.decryptedHeaders), this.mimePartNumber);

        headerSink.updateSecurityStatus(
          this.msgUriSpec,
          this.exitCode,
          this.returnStatus.statusFlags,
          this.returnStatus.keyId,
          this.returnStatus.userId,
          this.returnStatus.sigDetails,
          this.returnStatus.errorMsg,
          this.returnStatus.blockSeparation,
          this.uri,
          JSON.stringify({
            encryptedTo: this.returnStatus.encToDetails
          }),
          this.mimePartNumber);
      } else {
        this.updateHeadersInMsgDb();
      }
      this.statusDisplayed = true;
    } catch (ex) {
      EnigmailLog.writeException("mimeDecrypt.jsm", ex);
    }
    LOCAL_DEBUG("mimeDecrypt.jsm: displayStatus done\n");
  },

  handleResult: function(exitCode) {
    LOCAL_DEBUG("mimeDecrypt.jsm: done: " + exitCode + "\n");

    if (gDebugLogLevel > 4)
      LOCAL_DEBUG("mimeDecrypt.jsm: done: decrypted data='" + this.decryptedData + "'\n");

    // ensure newline at the end of the stream
    if (!this.decryptedData.endsWith("\n")) {
      this.decryptedData += "\r\n";
    }

    try {
      this.extractEncryptedHeaders();
      this.extractAutocryptGossip();
    } catch (ex) {}

    let i = this.decryptedData.search(/\n\r?\n/);
    if (i > 0) {
      var hdr = this.decryptedData.substr(0, i).split(/\r?\n/);
      for (let j = 0; j < hdr.length; j++) {
        if (hdr[j].search(/^\s*content-type:\s+text\/(plain|html)/i) >= 0) {
          LOCAL_DEBUG("mimeDecrypt.jsm: done: adding multipart/mixed around " + hdr[j] + "\n");

          this.addWrapperToDecryptedResult();
          break;
        }
      }
    }

    this.exitCode = exitCode;
  },

  addWrapperToDecryptedResult: function() {
    if (!this.isUrlEnigmailConvert()) {
      let wrapper = EnigmailMime.createBoundary();

      this.decryptedData = 'Content-Type: multipart/mixed; boundary="' + wrapper + '"\r\n' +
        'Content-Disposition: inline\r\n\r\n' +
        '--' + wrapper + '\r\n' +
        this.decryptedData + '\r\n' +
        '--' + wrapper + '--\r\n';
    }
  },

  extractContentType: function(data) {
    let i = data.search(/\n\r?\n/);
    if (i <= 0) return null;

    let headers = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    headers.initialize(data.substr(0, i));
    return headers.extractHeader("content-type", false);
  },

  // return data to libMime
  returnData: function(data) {
    EnigmailLog.DEBUG("mimeDecrypt.jsm: returnData: " + data.length + " bytes\n");

    let proto = null;
    let ct = this.extractContentType(data);
    if (ct && ct.search(/multipart\/signed/i) >= 0) {
      proto = EnigmailMime.getProtocol(ct);
    }

    try {
      if (proto && proto.search(/application\/(pgp|pkcs7|x-pkcs7)-signature/i) >= 0) {
        EnigmailLog.DEBUG("mimeDecrypt.jsm: returnData: using direct verification\n");
        this.mimeSvc.contentType = ct;
        if ("mimePart" in this.mimeSvc) {
          this.mimeSvc.mimePart = this.mimeSvc.mimePart + ".1";
        }
        let veri = EnigmailVerify.newVerifier(proto);
        veri.onStartRequest(this.mimeSvc, this.uri);
        veri.onTextData(data);
        veri.onStopRequest(null, 0);
      } else {
        if ("outputDecryptedData" in this.mimeSvc) {
          // TB >= 57
          this.mimeSvc.outputDecryptedData(data, data.length);
        } else {
          let gConv = Cc["@mozilla.org/io/string-input-stream;1"].createInstance(Ci.nsIStringInputStream);
          gConv.setData(data, data.length);
          this.mimeSvc.onStartRequest(null, null);
          this.mimeSvc.onDataAvailable(null, null, gConv, 0, data.length);
          this.mimeSvc.onStopRequest(null, null, 0);
        }
      }
    } catch (ex) {
      EnigmailLog.ERROR("mimeDecrypt.jsm: returnData(): mimeSvc.onDataAvailable failed:\n" + ex.toString());
    }
  },

  handleManualDecrypt: function() {

    try {
      let headerSink = EnigmailSingletons.messageReader;

      if (headerSink && this.uri && !this.backgroundJob) {
        headerSink.updateSecurityStatus(
          this.msgUriSpec,
          EnigmailConstants.POSSIBLE_PGPMIME,
          0,
          "",
          "",
          "",
          EnigmailLocale.getString("possiblyPgpMime"),
          "",
          this.uri,
          null,
          "");
      }
    } catch (ex) {}

    return 0;
  },

  updateHeadersInMsgDb: function() {
    if (this.mimePartNumber !== "1") return;
    if (!this.uri) return;

    if (this.decryptedHeaders && ("subject" in this.decryptedHeaders)) {
      try {
        let msgDbHdr = this.uri.QueryInterface(Ci.nsIMsgMessageUrl).messageHeader;
        msgDbHdr.subject = EnigmailData.convertFromUnicode(this.decryptedHeaders.subject, "utf-8");
      } catch (x) {}
    }
  },

  extractEncryptedHeaders: function() {
    let r = EnigmailMime.extractProtectedHeaders(this.decryptedData);
    if (!r) return;

    this.decryptedHeaders = r.newHeaders;
    if (r.startPos >= 0 && r.endPos > r.startPos) {
      this.decryptedData = this.decryptedData.substr(0, r.startPos) + this.decryptedData.substr(r.endPos);
    }
  },

  extractAutocryptGossip: async function() {
    let m1 = this.decryptedData.search(/^--/m);
    let m2 = this.decryptedData.search(/\r?\n\r?\n/);
    let m = Math.max(m1, m2);

    let hdr = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    hdr.initialize(this.decryptedData.substr(0, m));

    let gossip = hdr.getHeader("autocrypt-gossip") || [];
    EnigmailLog.DEBUG(`mimeDecrypt.jsm: extractAutocryptGossip: found ${gossip.length} headers\n`);

    let msgDate = null;
    try {
      msgDate = this.uri.QueryInterface(Ci.nsIMsgMessageUrl).messageHeader.dateInSeconds;
    } catch (x) {}


    for (let i in gossip) {
      let addr = EnigmailMime.getParameter(gossip[i], "addr");
      try {
        let r = await EnigmailAutocrypt.processAutocryptHeader(addr, [gossip[i].replace(/ /g, "")], msgDate, true, true);
        EnigmailLog.DEBUG(`mimeDecrypt.jsm: extractAutocryptGossip: r=${r}\n`);
      } catch (x) {
        EnigmailLog.DEBUG(`mimeDecrypt.jsm: extractAutocryptGossip: Error: ${x}\n`);
      }
    }
  }
};


////////////////////////////////////////////////////////////////////
// General-purpose functions, not exported

function LOCAL_DEBUG(str) {
  if (gDebugLogLevel) EnigmailLog.DEBUG(str);
}

function initModule() {
  var env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
  var nspr_log_modules = env.get("NSPR_LOG_MODULES");
  var matches = nspr_log_modules.match(/mimeDecrypt:(\d+)/);

  if (matches && (matches.length > 1)) {
    gDebugLogLevel = matches[1];
  }
}

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailMime"];

const jsmime = ChromeUtils.import("resource:///modules/jsmime.jsm").jsmime;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailRNG = ChromeUtils.import("chrome://enigmail/content/modules/rng.jsm").EnigmailRNG;
const EnigmailStreams = ChromeUtils.import("chrome://enigmail/content/modules/streams.jsm").EnigmailStreams;

var EnigmailMime = {
  /***
   * create a string of random characters suitable to use for a boundary in a
   * MIME message following RFC 2045
   *
   * @return: string of 33 random characters and digits
   */
  createBoundary: function() {
    return EnigmailRNG.generateRandomString(33);
  },

  /***
   * determine the "boundary" part of a mail content type.
   *
   * @contentTypeStr: the string containing all parts of a content-type.
   *               (e.g. multipart/mixed; boundary="xyz") --> returns "xyz"
   *
   * @return: String containing the boundary parameter; or ""
   */

  getBoundary: function(contentTypeStr) {
    return EnigmailMime.getParameter(contentTypeStr, "boundary");
  },

  /***
   * determine the "protocol" part of a mail content type.
   *
   * @contentTypeStr: the string containing all parts of a content-type.
   *               (e.g. multipart/signed; protocol="xyz") --> returns "xyz"
   *
   * @return: String containing the protocol parameter; or ""
   */

  getProtocol: function(contentTypeStr) {
    return EnigmailMime.getParameter(contentTypeStr, "protocol");
  },

  /***
   * determine an arbitrary "parameter" part of a mail header.
   *
   * @param headerStr: the string containing all parts of the header.
   * @param parameter: the parameter we are looking for
   *
   *
   * 'multipart/signed; protocol="xyz"', 'protocol' --> returns "xyz"
   *
   * @return: String containing the parameter; or ""
   */

  getParameter: function(headerStr, parameter) {
    let paramsArr = EnigmailMime.getAllParameters(headerStr);
    parameter = parameter.toLowerCase();
    if (parameter in paramsArr) {
      return paramsArr[parameter];
    }
    else
      return "";
  },

  /***
   * get all parameter attributes of a mail header.
   *
   * @param headerStr: the string containing all parts of the header.
   *
   * @return: Array of Object containing the key value pairs
   *
   * 'multipart/signed; protocol="xyz"'; boundary="xxx"
   *  --> returns [ ["protocol": "xyz"], ["boundary": "xxx"] ]
   */

  getAllParameters: function(headerStr) {

    headerStr = headerStr.replace(/[\r\n]+[ \t]+/g, "");
    let hdrMap = jsmime.headerparser.parseParameterHeader(";" + headerStr, true, true);

    let paramArr = [];
    let i = hdrMap.entries();
    let p = i.next();
    while (p.value) {
      paramArr[p.value[0].toLowerCase()] = p.value[1];
      p = i.next();
    }

    return paramArr;
  },

  /***
   * determine the "charset" part of a mail content type.
   *
   * @contentTypeStr: the string containing all parts of a content-type.
   *               (e.g. multipart/mixed; charset="utf-8") --> returns "utf-8"
   *
   * @return: String containing the charset parameter; or null
   */

  getCharset: function(contentTypeStr) {
    return EnigmailMime.getParameter(contentTypeStr, "charset");
  },

  /**
   * Convert a MIME header value into a UTF-8 encoded representation following RFC 2047
   */
  encodeHeaderValue: function(aStr) {
    let ret = "";

    if (aStr.search(/[^\x01-\x7F]/) >= 0) { // eslint-disable-line no-control-regex
      let s = EnigmailData.convertFromUnicode(aStr, "utf-8");
      ret = "=?UTF-8?B?" + btoa(s) + "?=";
    }
    else {
      ret = aStr;
    }

    return ret;
  },

  /**
   * format MIME header with maximum length of 72 characters.
   */
  formatHeaderData: function(hdrValue) {
    let header;
    if (Array.isArray(hdrValue)) {
      header = hdrValue.join("").split(" ");
    }
    else {
      header = hdrValue.split(/ +/);
    }

    let line = "";
    let lines = [];

    for (let i = 0; i < header.length; i++) {
      if (line.length + header[i].length >= 72) {
        lines.push(line + "\r\n");
        line = " " + header[i];
      }
      else {
        line += " " + header[i];
      }
    }

    lines.push(line);

    return lines.join("").trim();
  },

  /**
   * Correctly encode and format a set of email addresses for RFC 2047
   */
  formatEmailAddress: function(addressData) {
    const adrArr = addressData.split(/, */);

    for (let i in adrArr) {
      try {
        const m = adrArr[i].match(/(.*[\w\s]+?)<([\w-][\w.-]+@[\w-][\w.-]+[a-zA-Z]{1,4})>/);
        if (m && m.length == 3) {
          adrArr[i] = this.encodeHeaderValue(m[1]) + " <" + m[2] + ">";
        }
      }
      catch (ex) {}
    }

    return adrArr.join(", ");
  },

  /**
   * Extract the subject from the 1st line of the message body, if the message body starts
   * with: "Subject: ...\r?\n\r?\n".
   *
   * @param msgBody - String: message body
   *
   * @return
   * if subject is found:
   *  Object:
   *    - messageBody - String: message body without subject
   *    - subject     - String: extracted subject
   *
   * if subject not found: null
   */
  extractSubjectFromBody: function(msgBody) {
    let m = msgBody.match(/^(\r?\n?Subject: [^\r\n]+\r?\n\r?\n)/i);
    if (m && m.length > 0) {
      let subject = m[0].replace(/[\r\n]/g, "");
      subject = subject.substr(9);
      msgBody = msgBody.substr(m[0].length);

      return {
        messageBody: msgBody,
        subject: subject
      };
    }

    return null;
  },

  /***
   * determine if the message data contains a first mime part with content-type = "text/rfc822-headers"
   * if so, extract the corresponding field(s)
   */

  extractProtectedHeaders: function(contentData) {
    // find first MIME delimiter. Anything before that delimiter is the top MIME structure
    let m = contentData.search(/^--/m);

    let protectedHdr = ["subject", "date", "from",
      "to", "cc", "reply-to", "references",
      "newsgroups", "followup-to", "message-id"
    ];
    let newHeaders = {};

    // read headers of first MIME part and extract the boundary parameter
    let outerHdr = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    outerHdr.initialize(contentData.substr(0, m));

    let ct = outerHdr.extractHeader("content-type", false) || "";
    if (ct === "") return null;

    let startPos = -1,
      endPos = -1,
      bound = "";

    if (ct.search(/^multipart\//i) === 0) {
      // multipart/xyz message type
      if (m < 5) {
        return null;
      }


      bound = EnigmailMime.getBoundary(ct);
      if (bound === "") return null;

      // search for "outer" MIME delimiter(s)
      let r = new RegExp("^--" + bound, "mg");

      startPos = -1;
      endPos = -1;

      // 1st match: start of 1st MIME-subpart
      let match = r.exec(contentData);
      if (match && match.index) {
        startPos = match.index;
      }

      // 2nd  match: end of 1st MIME-subpart
      match = r.exec(contentData);
      if (match && match.index) {
        endPos = match.index;
      }

      if (startPos < 0 || endPos < 0) return null;
    }
    else {
      startPos = contentData.length;
      endPos = 0;
    }

    let headers = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    headers.initialize(contentData.substring(0, startPos));

    // we got a potentially protected header. Let's check ...
    ct = headers.extractHeader("content-type", false) || "";
    if (this.getParameter(ct, "protected-headers").search(/^v1$/i) !== 0) return null;

    for (let i in protectedHdr) {
      if (headers.hasHeader(protectedHdr[i])) {
        newHeaders[protectedHdr[i]] = jsmime.headerparser.decodeRFC2047Words(headers.extractHeader(protectedHdr[i], true)) || undefined;
      }
    }

    // contentBody holds the complete 1st MIME part
    let contentBody = contentData.substring(startPos + bound.length + 3, endPos);
    let i = contentBody.search(/^[A-Za-z]/m); // skip empty lines
    if (i > 0) {
      contentBody = contentBody.substr(i);
    }

    headers.initialize(contentBody);

    let innerCt = headers.extractHeader("content-type", false) || "";

    if (innerCt.search(/^text\/rfc822-headers/i) === 0) {

      let charset = EnigmailMime.getCharset(innerCt);
      let ctt = headers.extractHeader("content-transfer-encoding", false) || "";

      // determine where the headers end and the MIME-subpart body starts
      let bodyStartPos = contentBody.search(/\r?\n\s*\r?\n/) + 1;

      if (bodyStartPos < 10) return null;

      bodyStartPos += contentBody.substr(bodyStartPos).search(/^[A-Za-z]/m);

      let ctBodyData = contentBody.substr(bodyStartPos);

      if (ctt.search(/^base64/i) === 0) {
        ctBodyData = EnigmailData.decodeBase64(ctBodyData) + "\n";
      }
      else if (ctt.search(/^quoted-printable/i) === 0) {
        ctBodyData = EnigmailData.decodeQuotedPrintable(ctBodyData) + "\n";
      }

      if (charset) {
        ctBodyData = EnigmailData.convertToUnicode(ctBodyData, charset);
      }

      // get the headers of the MIME-subpart body --> that's the ones we need
      let bodyHdr = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
      bodyHdr.initialize(ctBodyData);

      for (let i in protectedHdr) {
        if (bodyHdr.hasHeader(protectedHdr[i])) {
          newHeaders[protectedHdr[i]] = jsmime.headerparser.decodeRFC2047Words(bodyHdr.extractHeader(protectedHdr[i], true)) || undefined;
        }
      }
    }
    else {
      if (!(innerCt.search(/^text\/plain/i) === 0 && innerCt.search(/; *protected-headers="v1"/i) > 0)) {
        startPos = -1;
        endPos = -1;
      }
    }

    return {
      newHeaders: newHeaders,
      startPos: startPos,
      endPos: endPos,
      securityLevel: 0
    };
  },

  /**
   * Get the part number from a URI spec (e.g. mailbox:///folder/xyz?part=1.2.3.5)
   *
   * @param spec: String - the URI spec to inspect
   *
   * @return String: the mime part number (or "" if none found)
   */
  getMimePartNumber: function(spec) {
    let m = spec.match(/([\?&]part=)(\d+(\.\d+)*)/);

    if (m && m.length >= 3) {
      return m[2];
    }

    return "";
  },

  /**
   * Try to determine if the message structure is a known MIME structure,
   * based on the MIME part number and the uriSpec.
   *
   * @param mimePartNumber: String - the MIME part we are requested to decrypt
   * @param uriSpec:        String - the URI spec of the message (or msg part) loaded by TB
   *
   * @return Boolean: true: regular message structure, MIME part is safe to be decrypted
   *                  false: otherwise
   */
  isRegularMimeStructure: function(mimePartNumber, uriSpec, acceptSubParts = false) {
    if (mimePartNumber.length === 0) return true;

    if (acceptSubParts && (mimePartNumber.search(/^1(\.1)*$/) === 0)) return true;
    if (mimePartNumber === "1") return true;

    if (!uriSpec) return true;

    // is the message a subpart of a complete attachment?
    let msgPart = this.getMimePartNumber(uriSpec);
    if (msgPart.length > 0) {
      // load attached messages
      if (mimePartNumber.indexOf(msgPart) === 0 &&
        mimePartNumber.substr(msgPart.length).search(/^(\.1)+$/) === 0) return true;

      // load attachments of attached messages
      if (msgPart.indexOf(mimePartNumber) === 0 &&
        uriSpec.search(/[\?&]filename=/) > 0) return true;
    }

    return false;
  },


  /**
   * Parse a MIME message and return a tree structur of TreeObject
   *
   * @param url:         String   - the URL to load and parse
   * @param getBody:     Boolean  - if true, delivers the body text of each MIME part
   * @param callbackFunc Function - the callback function that is called asynchronously
   *                                when parsing is complete.
   *                                Function signature: callBackFunc(TreeObject)
   *
   * @return undefined
   */
  getMimeTreeFromUrl: function(url, getBody = false, callbackFunc) {
    function onData(data) {
      let tree = getMimeTree(data, getBody);
      callbackFunc(tree);
    }

    let chan = EnigmailStreams.createChannel(url);
    let bufferListener = EnigmailStreams.newStringStreamListener(onData);
    chan.asyncOpen(bufferListener, null);
  },

  getMimeTree: getMimeTree

};

/**
 * Parse a MIME message and return a tree structure of TreeObject.
 *
 * TreeObject contains the following main parts:
 *     - partNum: String
 *     - headers: Map, containing all headers.
 *         Special headers for contentType and charset
 *     - body: String, if getBody == true
 *     - subParts: Array of TreeObject
 *
 * @param mimeStr: String  - a MIME structure to parse
 * @param getBody: Boolean - if true, delivers the body text of each MIME part
 *
 * @return TreeObject, or NULL in case of failure
 */
function getMimeTree(mimeStr, getBody = false) {

  let mimeTree = {
      partNum: "",
      headers: null,
      body: "",
      parent: null,
      subParts: []
    },
    stack = [],
    currentPart = "",
    currPartNum = "";

  const jsmimeEmitter = {

    createPartObj: function(partNum, headers, parent) {
      let ct;

      if (headers.has("content-type")) {
        ct = headers.contentType.type;
        let it = headers.get("content-type").entries();
        for (let i of it) {
          ct += '; ' + i[0] + '="' + i[1] + '"';
        }
      }

      return {
        partNum: partNum,
        headers: headers,
        fullContentType: ct,
        body: "",
        parent: parent,
        subParts: []
      };
    },

    /** JSMime API **/
    startMessage: function() {
      currentPart = mimeTree;
    },

    endMessage: function() {},

    startPart: function(partNum, headers) {
      //dump("mime.jsm: jsmimeEmitter.startPart: partNum=" + partNum + "\n");
      partNum = "1" + (partNum !== "" ? "." : "") + partNum;
      let newPart = this.createPartObj(partNum, headers, currentPart);

      if (partNum.indexOf(currPartNum) === 0) {
        // found sub-part
        currentPart.subParts.push(newPart);
      }
      else {
        // found same or higher level
        currentPart.subParts.push(newPart);
      }
      currPartNum = partNum;
      currentPart = newPart;
    },
    endPart: function(partNum) {
      //dump("mime.jsm: jsmimeEmitter.startPart: partNum=" + partNum + "\n");
      currentPart = currentPart.parent;
    },

    deliverPartData: function(partNum, data) {
      //dump("mime.jsm: jsmimeEmitter.deliverPartData: partNum=" + partNum + " / " + typeof data + "\n");
      if (typeof(data) === "string") {
        currentPart.body += data;
      }
      else {
        currentPart.body += EnigmailData.arrayBufferToString(data);
      }
    }
  };

  let opt = {
    strformat: "unicode",
    bodyformat: getBody ? "decode" : "none"
  };


  try {
    let p = new jsmime.MimeParser(jsmimeEmitter, opt);
    p.deliverData(mimeStr);
    return mimeTree.subParts[0];
  }
  catch (ex) {
    return null;
  }
}

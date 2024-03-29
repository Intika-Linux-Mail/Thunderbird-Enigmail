/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, do_test_pending: false, do_test_finished: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js"); /*global TestHelper: false, component: false, withTestGpgHome: false, withEnigmail: false */
TestHelper.loadDirectly("tests/mailHelper.js"); /*global MailHelper: false */

testing("persistentCrypto.jsm"); /*global EnigmailPersistentCrypto: false, EnigmailMime: false */
var EnigmailKeyRing = component("enigmail/keyRing.jsm").EnigmailKeyRing;
/*global MsgHdrToMimeMessage: false, MimeMessage: false, MimeContainer: false, EnigmailStreams: false,
  EnigmailCompat: false */

const inspector = Cc["@mozilla.org/jsinspector;1"].createInstance(Ci.nsIJSInspector);

const copyListener = {
  QueryInterface: function(iid) {
    if (iid.equals(Ci.nsIMsgCopyServiceListener) || iid.equals(Ci.nsISupports)) {
      return this;
    }
    throw Components.results.NS_NOINTERFACE;
  },
  GetMessageId: function(messageId) {},
  OnProgress: function(progress, progressMax) {},
  OnStartCopy: function() {},
  SetMessageKey: function(key) {}
};


test(withTestGpgHome(withEnigmail(function messageIsCopiedToNewDir() {
  loadSecretKey();
  MailHelper.cleanMailFolder(MailHelper.getRootFolder());
  const sourceFolder = MailHelper.createMailFolder("source-box");
  MailHelper.loadEmailToMailFolder("resources/encrypted-email.eml", sourceFolder);

  const header = MailHelper.fetchFirstMessageHeaderIn(sourceFolder);
  const targetFolder = MailHelper.createMailFolder("target-box");
  const move = false;

  copyListener.OnStopCopy = function(statusCode) {
    Assert.equal(targetFolder.getTotalMessages(false), 1);
    Assert.equal(sourceFolder.getTotalMessages(false), 1);
    inspector.exitNestedEventLoop();
  };
  EnigmailPersistentCrypto.dispatchMessages([header], targetFolder.URI, copyListener, move);
  inspector.enterNestedEventLoop(0);

})));

test(withTestGpgHome(withEnigmail(function messageIsMovedToNewDir() {
  loadSecretKey();
  MailHelper.cleanMailFolder(MailHelper.rootFolder);
  const sourceFolder = MailHelper.createMailFolder("source-box");
  MailHelper.loadEmailToMailFolder("resources/encrypted-email.eml", sourceFolder);

  const header = MailHelper.fetchFirstMessageHeaderIn(sourceFolder);
  const targetFolder = MailHelper.createMailFolder("target-box");
  const move = true;

  copyListener.OnStopCopy = function(statusCode) {
    inspector.exitNestedEventLoop();
  };
  EnigmailPersistentCrypto.dispatchMessages([header], targetFolder.URI, copyListener, move);
  inspector.enterNestedEventLoop(0);

})));

test(withTestGpgHome(withEnigmail(function messageIsMovedAndDecrypted() {
  loadSecretKey();
  MailHelper.cleanMailFolder(MailHelper.rootFolder);
  const sourceFolder = MailHelper.createMailFolder("source-box");
  MailHelper.loadEmailToMailFolder("resources/encrypted-pgpmime-email.eml", sourceFolder);

  const header = MailHelper.fetchFirstMessageHeaderIn(sourceFolder);
  const targetFolder = MailHelper.createMailFolder("target-box");
  const move = true;
  copyListener.OnStopCopy = function(statusCode) {
    Assert.equal(targetFolder.getTotalMessages(false), 1);
    inspector.exitNestedEventLoop();
  };

  EnigmailPersistentCrypto.dispatchMessages([header], targetFolder.URI, copyListener, move);
  inspector.enterNestedEventLoop(0);

  const dispatchedHeader = MailHelper.fetchFirstMessageHeaderIn(targetFolder);
  Assert.ok(dispatchedHeader !== null);

  let msgUriSpec = dispatchedHeader.folder.getUriForMsg(dispatchedHeader);
  let urlObj = EnigmailCompat.getUrlFromUriSpec(msgUriSpec);

  EnigmailMime.getMimeTreeFromUrl(
    urlObj.spec,
    true,
    function(mimeTree) {
      Assert.equal(mimeTree.subParts.length, 1);
      if (mimeTree.subParts.length > 0) {
        Assert.assertContains(mimeTree.subParts[0].body, "This message is encrypted");
      }
      inspector.exitNestedEventLoop();
    },
    false
  );
  inspector.enterNestedEventLoop(0);
})));


test(withTestGpgHome(withEnigmail(function messageWithAttachemntIsMovedAndDecrypted() {
  loadSecretKey();
  loadPublicKey();
  MailHelper.cleanMailFolder(MailHelper.getRootFolder());
  const sourceFolder = MailHelper.createMailFolder("source-box");
  MailHelper.loadEmailToMailFolder("resources/encrypted-email-with-attachment.eml", sourceFolder);

  const header = MailHelper.fetchFirstMessageHeaderIn(sourceFolder);
  const targetFolder = MailHelper.createMailFolder("target-box");
  const move = true;
  copyListener.OnStopCopy = function(statusCode) {
    inspector.exitNestedEventLoop();
  };
  EnigmailPersistentCrypto.dispatchMessages([header], targetFolder.URI, copyListener, move);
  inspector.enterNestedEventLoop(0);

  const dispatchedHeader = MailHelper.fetchFirstMessageHeaderIn(targetFolder);
  Assert.ok(dispatchedHeader !== null);

  let msgUriSpec = dispatchedHeader.folder.getUriForMsg(dispatchedHeader);
  let urlObj = EnigmailCompat.getUrlFromUriSpec(msgUriSpec);

  do_test_pending();
  EnigmailMime.getMimeTreeFromUrl(
    urlObj.spec,
    true,
    function(mimeTree) {
      Assert.assertContains(mimeTree.subParts[0].body, "This is encrypted");
      Assert.equal(mimeTree.subParts.length, 2);
      if (mimeTree.subParts.length >= 2) {
        Assert.assertContains(mimeTree.subParts[1].body, "This is an attachment.");
      }
      do_test_finished();
    },
    false
  );
})));

test(withTestGpgHome(withEnigmail(function messageWithAttachemntIsMovedAndReEncrypted() {
  loadSecretKey();
  loadPublicKey();
  MailHelper.cleanMailFolder(MailHelper.getRootFolder());
  const sourceFolder = MailHelper.createMailFolder("source-box");
  MailHelper.loadEmailToMailFolder("resources/encrypted-email-with-attachment.eml", sourceFolder);

  const header = MailHelper.fetchFirstMessageHeaderIn(sourceFolder);
  const targetFolder = MailHelper.createMailFolder("target-box");
  const move = true;
  copyListener.OnStopCopy = function(statusCode) {
    inspector.exitNestedEventLoop();
  };

  let keyObj = EnigmailKeyRing.getKeyById("0x65537E212DC19025AD38EDB2781617319CE311C4");
  EnigmailPersistentCrypto.dispatchMessages([header], targetFolder.URI, copyListener, move, keyObj);
  inspector.enterNestedEventLoop(0);

  const dispatchedHeader = MailHelper.fetchFirstMessageHeaderIn(targetFolder);
  Assert.ok(dispatchedHeader !== null);

  let msgUriSpec = dispatchedHeader.folder.getUriForMsg(dispatchedHeader);
  let urlObj = EnigmailCompat.getUrlFromUriSpec(msgUriSpec);

  EnigmailMime.getMimeTreeFromUrl(
    urlObj.spec,
    true,
    function(mimeTree) {
      Assert.assertContains(mimeTree.headers._rawHeaders.get("content-type")[0], "multipart/encrypted");
      Assert.assertContains(mimeTree.subParts[0].body, "Version: 1");
      Assert.equal(mimeTree.subParts.length, 2);
      if (mimeTree.subParts.length >= 2) {
        Assert.assertContains(mimeTree.subParts[1].body, "---BEGIN PGP MESSAGE---");
      }
      inspector.exitNestedEventLoop();
    },
    false
  );
  inspector.enterNestedEventLoop(0);
})));

var loadSecretKey = function() {
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  EnigmailKeyRing.importKeyFromFile(secretKey, [], {});
};

var loadPublicKey = function() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  EnigmailKeyRing.importKeyFromFile(publicKey, [], {});
};

function stringFromUrl(url) {
  const inspector = Cc["@mozilla.org/jsinspector;1"].getService(Ci.nsIJSInspector);
  let result = null;
  const p = new Promise(function(resolve, reject) {
    const iOService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
    const uri = iOService.newURI(url, null, null);
    const attChannel = EnigmailStreams.createChannel(uri);
    const listener = EnigmailStreams.newStringStreamListener(function(data) {
      result = data;
      inspector.exitNestedEventLoop();
      resolve();
    });
    attChannel.asyncOpen(listener, uri);
  });

  if (!result) {
    inspector.enterNestedEventLoop({
      value: 0
    });
  }
  return result;
}

function extractAttachment(att) {
  const name = att.name;
  const body = stringFromUrl(att.url);
  const isEncrypted = att.isEncrypted;
  return {
    name: name,
    body: body,
    isEncrypted: isEncrypted
  };
}

function extractAttachments(msg) {
  const result = [];
  for (let i = 0; i < msg.allAttachments.length; i++) {
    result.push(extractAttachment(msg.allAttachments[i]));
  }
  return result;
}

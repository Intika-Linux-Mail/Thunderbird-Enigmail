/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/**
 * This is a dummy dummy module for pEp
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailpEp"];


var EnigmailpEp = {

  getPepVersion: function() {
    return null;
  },

  getPepHomeDir: function() {
    return null;
  },

  getConnectionInfo: function() {
    return null;
  },

  getGpgEnv: function() {
    return null;
  },


  registerLogHandler: function(logFunction) {},

  encryptMessage: function(fromAddr, toAddrList, subject, messageObj, pEpMode) {
    return null;
  },


  encryptMimeString: function(mimeStr, pEpMode, encryptFlags = 0) {
    return null;
  },

  decryptMessage: function(message, sender, to, cc, replyTo) {
    return null;
  },



  decryptMimeString: function(mimeStr) {
    return null;
  },

  getIdentityRating: function(userId) {
    return null;
  },

  setMyself: function(idObject) {
    return null;
  },

  updateIdentity: function(idObject) {
    return null;
  },


  getOwnIdentities: function() {
    return null;
  },


  getTrustWords: function(id1, id2, language, longList = false) {
    return null;
  },


  trustIdentity: function(idObject) {
    return null;
  },


  resetIdentityTrust: function(idObject) {
    return null;
  },

  mistrustIdentity: function(idObject) {
    return null;
  },

  deliverHandshakeResult: function(partnerId, resultValue) {
    return null;
  },


  getLanguageList: function() {
    return null;
  },


  processLanguageList: function(languageStr) {
    return null;
  },


  outgoingMessageRating: function(from, to, message) {
    return null;
  },

  blacklistGetKeyList: function() {
    return null;
  },

  blacklistAddKey: function(fpr) {
    return null;
  },

  blacklistDeleteKey: function(fpr) {
    return null;
  },


  startKeyserverLookup: function() {
    return null;
  },

  stopKeyserverLookup: function() {
    return null;
  },

  startKeySync: function() {
    return null;
  },

  stopKeySync: function() {
    return null;
  },

  setPassiveMode: function(isPassive) {
    return null;
  },

  shutdown: function() {
    return null;
  },

  registerTbListener: function(port, securityToken) {
    return null;
  },


  registerListener: function() {
    return null;
  },

  unregisterListener: function(port, securityToken) {
    return null;
  },

  parseJSON: function(str) {
    return null;
  },

  setServerPath: function(pathName) {
    return null;
  },

  setAdapterApiVersion: function(v) {
    return null;
  },

  checkAdapterApiLevel: function(requiredVersion) {
    return false;
  }
};

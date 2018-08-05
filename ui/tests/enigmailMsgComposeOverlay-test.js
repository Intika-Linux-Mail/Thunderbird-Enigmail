/*global Enigmail: false, Assert: false, do_load_module: false, trustAllKeys_test: false, JSUnit: false, Components: false, EnigmailConstants: false, EnigmailLocale: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


var window;
var document;

var EnigmailApp = {};
var getCurrentAccountKey = {};
var MailServices = {};
var CommandUpdate_MsgCompose = {};
var top = {};
var EnigmailDialog = {};
var AddAttachment;
var AddAttachments;
var EnigmailMsgCompFields = {};
var EnigmailPEPAdapter = {};
var Recipients2CompFields = {};
var MailUtils = {};
var GetResourceFromUri = {};
var EnigmailCore = {};

var gSMFields;
var EnigmailPrefs = {
  getPref : (prop) => {
    return 1;
  }
};

var EnigmailTimer = {
  setTimeout : function(){}
};

var gMsgCompose = {};

function toggleEncryptMessage(){
  Assert.ok(true);
}

function toggleSignMessage(){
  Assert.ok(true);
}

var getCurrentIdentity = function(){

};

var EnigmailFuncs = {

};

//const cu = Components.utils;
//let consol = (cu.import("resource://gre/modules/Console.jsm", {})).console;

function processFinalState_test() {
  // Encryption Status and Reason

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.getAccDefault = (prop) => {
    //Function Overriding
    if(prop === "signIfEnc" || prop === "signIfNotEnc" || prop === "signIfNotEnc" || prop === "signIfEnc" || prop === "sign-pgp" || prop === "encrypt"){
      return true;
    }
    else {
      return false;
    }
  };

  // Testing Encryption Flags

  //Encryption reasonManuallyForced
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonManuallyForced"));

  //Encryption reasonManuallyForced
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonManuallyForced"));

  //Encryption reasonByRecipientRules
  Enigmail.msg.encryptForced = null;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonByRecipientRules"));

  //Encryption reasonEnabledByDefault
  Enigmail.msg.encryptByRules =  EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0002;
  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted,  EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonEnabledByDefault"));

  //Encryption reasonEmpty
  Enigmail.msg.encryptByRules =  EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonEncrypted, "");

  //Encryption reasonByRecipientRules
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonByRecipientRules"));

  //Encryption reasonByAutoEncryption
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_AUTO_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonByAutoEncryption"));

  //Encryption reasonByConflict
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonByConflict"));

  //Signing of Key

  //Signing reasonManuallyForced
  Enigmail.msg.signForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonManuallyForced"));

  //Signing reasonManuallyForced
  Enigmail.msg.signForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonManuallyForced"));

  //Signing reasonByRecipientRules
  Enigmail.msg.signForced = null;
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByRecipientRules"));

  //Signing reasonEnabledByDefault
  Enigmail.msg.signByRules =  EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.finalSignDependsOnEncrypt = false;
  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.getAccDefault = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned,  EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonEnabledByDefault"));

  //Signing reasonEmpty
  Enigmail.msg.signByRules =  EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0002;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonSigned, "");

  //Signing reasonByRecipientRules
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByRecipientRules"));

  //Signing reasonByConflict
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByConflict"));

  //finalSignDependsOnEncrypt Cases

  //Encryption ENIG_ALWAYS
  Enigmail.msg.isEnigmailEnabled = () => {
    return true;
  };
  Enigmail.msg.signByRules =  EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.finalSignDependsOnEncrypt = true;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByEncryptionMode"));

  //Encryption ENIG_NEVER
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByEncryptionMode"));

  //Encryption encFinally = EnigmailConstants;
  Enigmail.msg.encryptForced = null;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonByEncryptionMode"));

  //Encryption ENIG_CONFLICT
  Enigmail.msg.getAccDefault = (prop) => {
    //Function Overriding
    return false;
  };
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonSigned, "");

  //statusPGPMime Flags

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_FORCENO);

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_FORCEYES);

  Enigmail.msg.pgpmimeForced = "";
  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_NO);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_YES);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_CONFLICT);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_NO);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = EnigmailConstants.SEND_PGP_MIME;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_YES);

}

function trustAllKeys_test() {
  // test functionality of trustAllKeys
  Enigmail.msg.trustAllKeys = true;
  Enigmail.msg.tempTrustAllKeys();
  Assert.equal(Enigmail.msg.trustAllKeys, false, "check trustAllKeys is false");

  Enigmail.msg.tempTrustAllKeys();
  Assert.equal(Enigmail.msg.trustAllKeys, true, "check trustAllKeys is true");

}

function setFinalSendMode_test() {
  // test functionality of setFinalSendMode

  Enigmail.msg.determineSendFlags = () => {

  };

  Enigmail.msg.setFinalSendMode('final-encryptDefault');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_UNDEF);

  Enigmail.msg.setFinalSendMode('final-encryptYes');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.setFinalSendMode('final-encryptNo');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.setFinalSendMode('final-signDefault');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_UNDEF);

  Enigmail.msg.setFinalSendMode('final-signYes');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.setFinalSendMode('final-signNo');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.setFinalSendMode('final-pgpmimeDefault');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);

  Enigmail.msg.setFinalSendMode('final-pgpmimeYes');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.setFinalSendMode('final-pgpmimeNo');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.setFinalSendMode('final-useSmime');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_FORCE_SMIME);

  Enigmail.msg.statusSigned = EnigmailConstants.ENIG_FINAL_FORCENO;
  Enigmail.msg.setFinalSendMode('toggle-final-sign');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.statusSigned = EnigmailConstants.ENIG_FINAL_FORCENO;
  Enigmail.msg.setFinalSendMode('toggle-final-sign');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.statusSigned = EnigmailConstants.ENIG_FINAL_FORCEYES;
  Enigmail.msg.setFinalSendMode('toggle-final-sign');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.statusSigned = EnigmailConstants.ENIG_FINAL_CONFLICT;
  Enigmail.msg.setFinalSendMode('toggle-final-sign');
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.juniorMode = false;

  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_FORCENO;
  Enigmail.msg.setFinalSendMode('toggle-final-encrypt');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_FORCEYES;
  Enigmail.msg.setFinalSendMode('toggle-final-encrypt');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_CONFLICT;
  Enigmail.msg.setFinalSendMode('toggle-final-encrypt');
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_FORCENO;
  Enigmail.msg.setFinalSendMode('toggle-final-mime');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_ALWAYS);

  Enigmail.msg.statusPGPMime= EnigmailConstants.ENIG_FINAL_FORCEYES;
  Enigmail.msg.setFinalSendMode('toggle-final-mime');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_NEVER);

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_CONFLICT;
  Enigmail.msg.setFinalSendMode('toggle-final-mime');
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_NEVER);
  Assert.equal(Enigmail.msg.sendModeDirty, true);

}

function signingNoLongerDependsOnEnc_test() {
  Enigmail.msg.finalSignDependsOnEncrypt = true;
  Enigmail.msg.juniorMode = true;
  Enigmail.msg.signingNoLongerDependsOnEnc();
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

  Enigmail.msg.juniorMode = false;
  EnigmailDialog.alertPref = function(){};
  Enigmail.msg.signingNoLongerDependsOnEnc();
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);
}


function toggleSMimeEncrypt_test() {

  gSMFields = {
    requireEncryptMessage : true
  };
  Enigmail.msg.toggleSMimeEncrypt();
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_ALWAYS);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_FORCE_SMIME);

  gSMFields = {
    requireEncryptMessage : false,
    signMessage : false
  };
  Enigmail.msg.toggleSMimeEncrypt();
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_NEVER);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);

}

function toggleSMimeSign_test() {
  gSMFields = {
    signMessage : true
  };
  Enigmail.msg.toggleSMimeSign();
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_ALWAYS);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_FORCE_SMIME);

  gSMFields = {
    requireEncryptMessage : false,
    signMessage : false
  };
  Enigmail.msg.toggleSMimeSign();
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_NEVER);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);

}

function tryEnablingSMime_test() {

  gSMFields = {};

  var encFinally = EnigmailConstants.ENIG_FINAL_FORCENO;
  var signFinally = EnigmailConstants.ENIG_FINAL_FORCENO;
  var ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  Enigmail.msg.mimePreferOpenPGP = 1;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_ALWAYS;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  Enigmail.msg.mimePreferOpenPGP = 1;
  Enigmail.msg.encryptByRules = null;
  Enigmail.msg.autoPgpEncryption = 1;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  Enigmail.msg.mimePreferOpenPGP = 0;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.autoPgpEncryption = 0;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  Enigmail.msg.encryptByRules = null;
  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_NEVER;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_ALWAYS;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);


  encFinally = EnigmailConstants.ENIG_FINAL_FORCEYES;
  signFinally = EnigmailConstants.ENIG_FINAL_YES;
  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_FORCE_SMIME;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_FORCESMIME);
  Assert.equal(gSMFields.requireEncryptMessage, true);
  Assert.equal(gSMFields.signMessage, true);


  Enigmail.msg.isSmimeEncryptionPossible = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.tryEnablingSMime.autoSendEncrypted = 0;
  Enigmail.msg.pgpmimeForced = null;
  Enigmail.msg.mimePreferOpenPGP = 0;
  encFinally = EnigmailConstants.ENIG_FINAL_FORCEYES;
  signFinally = EnigmailConstants.ENIG_FINAL_FORCENO;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_SMIME);
  Assert.equal(gSMFields.requireEncryptMessage, true);
  Assert.equal(gSMFields.signMessage, false);

  Enigmail.msg.autoPgpEncryption = false;
  Enigmail.msg.mimePreferOpenPGP = null;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_SMIME);
  Assert.equal(gSMFields.requireEncryptMessage, true);
  Assert.equal(gSMFields.signMessage, false);

  Enigmail.msg.isSmimeEncryptionPossible = () => {
    //Function Overriding
    return false;
  };
  Enigmail.msg.autoPgpEncryption = true;
  encFinally = EnigmailConstants.ENIG_FINAL_NO;
  signFinally = EnigmailConstants.ENIG_FINAL_YES;
  Enigmail.msg.mimePreferOpenPGP = 0;
  Enigmail.msg.autoPgpEncryption = false;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_SMIME);
  Assert.equal(gSMFields.requireEncryptMessage, false);
  Assert.equal(gSMFields.signMessage, true);


  encFinally = EnigmailConstants.ENIG_FINAL_FORCENO;
  signFinally = EnigmailConstants.ENIG_FINAL_FORCEYES;
  Enigmail.msg.autoPgpEncryption = true;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_SMIME);
  Assert.equal(gSMFields.requireEncryptMessage, false);
  Assert.equal(gSMFields.signMessage, false);


  EnigmailPrefs = {
    getPref : (prop) => {
      //Function Overriding
      return 0;
    }
  };

  Enigmail.msg.isSmimeEncryptionPossible = () => {
    //Function Overriding
    return true;
  };

  encFinally = EnigmailConstants.ENIG_FINAL_FORCEYES;
  signFinally = EnigmailConstants.ENIG_FINAL_FORCEYES;
  Enigmail.msg.autoPgpEncryption = false;
  Enigmail.msg.mimePreferOpenPGP = null;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_SMIME);
  Assert.equal(gSMFields.requireEncryptMessage, true);
  Assert.equal(gSMFields.signMessage, true);

  Enigmail.msg.statusPGPMime = null;
  Enigmail.msg.autoPgpEncryption = true;
  Enigmail.msg.mimePreferOpenPGP = null;
  ret = Enigmail.msg.tryEnablingSMime(encFinally, signFinally);
  Assert.equal(ret.encFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(ret.signFinally, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.statusPGPMime, null);
  Assert.equal(gSMFields.requireEncryptMessage, false);
  Assert.equal(gSMFields.signMessage, false);

}

function setSendMode_test() {

  Enigmail.msg.processFinalState = () => {
    //Function Overriding
    return null;
  };

  Enigmail.msg.updateStatusBar = () => {
    //Function Overriding
    return null;
  };

  Enigmail.msg.sendMode = EnigmailConstants.SEND_SIGNED;
  Enigmail.msg.setSendMode('sign');
  Assert.equal(Enigmail.msg.sendMode, EnigmailConstants.SEND_SIGNED);

  Enigmail.msg.sendMode = EnigmailConstants.SEND_ENCRYPTED;
  Enigmail.msg.setSendMode('sign');
  Assert.equal(Enigmail.msg.sendMode, 3);

  Enigmail.msg.sendMode = EnigmailConstants.SEND_ENCRYPTED;
  Enigmail.msg.setSendMode('encrypt');
  Assert.equal(Enigmail.msg.sendMode, EnigmailConstants.SEND_ENCRYPTED);

  Enigmail.msg.sendMode = EnigmailConstants.SEND_SIGNED;
  Enigmail.msg.setSendMode('encrypt');
  Assert.equal(Enigmail.msg.sendMode, 3);

}


function getAccDefault_test() {

  Enigmail.msg.identity = {};

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 0;
  };

  let ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 1;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 1;
  };

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_FORCE_SMIME;

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_FORCE_ALWAYS;

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, true);

  Enigmail.msg.pgpmimeForced = null;
  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('sign-pgp');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return false;
  };

  ret = Enigmail.msg.getAccDefault('pgpMimeMode');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault("signIfNotEnc");
  Assert.equal(ret, false);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return true;
  };

  ret = Enigmail.msg.getAccDefault("signIfEnc");
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('attachPgpKey');
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 0;
  };

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('random');
  Assert.equal(ret, false);

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('signIfNotEnc');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('signIfEnc');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('pgpMimeMode');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('attachPgpKey');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('sign-pgp');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('random');
  Assert.equal(ret, null);
}

function toggleAccountAttr_test(){

  Enigmail.msg.identity = {};

  let attr_name = 'random';
  Enigmail.msg.identity.getBoolAttribute = function(){
    //Function Overriding
    return true;
  };

  Enigmail.msg.identity.setBoolAttribute = function(attrName, oldValue){
    //Function Overriding
    Assert.equal(attrName, attr_name);
    Assert.equal(oldValue, false);
  };

  Enigmail.msg.toggleAccountAttr(attr_name);

}

function toggleAttribute_test(){

  let attr_name = 'random';
  EnigmailPrefs.getPref = function(){
    //Function Overriding
    return true;
  };

  EnigmailPrefs.setPref = function(attrName, oldValue){
    //Function Overriding
    Assert.equal(attrName, attr_name);
    Assert.equal(oldValue, false);
  };

  Enigmail.msg.toggleAttribute(attr_name);

}

function fixMessageSubject_test(){
  let check = "";
  document.getElementById = function(){
    return {
      value : "Re: Re: Hello",
      oninput : function(){
        Assert.ok(true);
      }
    };
  };

  Enigmail.msg.fixMessageSubject();

}

function notifyUser_test(){
  let msgText = "Hello",
    messageId = "12",
    detailsText = "Text";

  document.getElementById = function(){
    return {
      appendNotification : function(msg_text, message_id, str, prio, button_arr){
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 1);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM : 1,
      PRIORITY_INFO_MEDIUM : 3,
      PRIORITY_WARNING_MEDIUM : 2
    };
  };
  Enigmail.msg.notifyUser(1, msgText, messageId, detailsText);

  document.getElementById = function(){
    return {
      appendNotification : function(msg_text, message_id, str, prio, button_arr){
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 2);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM : 1,
      PRIORITY_INFO_MEDIUM : 3,
      PRIORITY_WARNING_MEDIUM : 2
    };
  };
  Enigmail.msg.notifyUser(2, msgText, messageId, detailsText);

  document.getElementById = function(){
    return {
      appendNotification : function(msg_text, message_id, str, prio, button_arr){
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 3);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM : 1,
      PRIORITY_INFO_MEDIUM : 3,
      PRIORITY_WARNING_MEDIUM : 2
    };
  };
  Enigmail.msg.notifyUser(3, msgText, messageId, detailsText);
}

function setIdentityCallback_test(){

  Enigmail.msg.setIdentityDefaults = function(){
    //Function Overriding
    Assert.ok(true);
  };

  Enigmail.msg.setIdentityCallback('xyz');
}

function toggleSmimeToolbar_test(){

  Enigmail.msg.toggleSMimeEncrypt = function(){
    //Function Overriding
    Assert.ok(true);
  };

  Enigmail.msg.toggleSMimeSign = function(){
    //Function Overriding
    Assert.ok(true);
  };

  let event  = {
    'target' : {
      'id' : "menu_securitySign2"
    },
    stopPropagation : function(){
      Assert.ok(true);
    }
  };
  Enigmail.msg.toggleSmimeToolbar(event);

  event  = {
    'target' : {
      'id' : "menu_securityEncryptRequire2"
    },
    stopPropagation : function(){
      Assert.ok(true);
    }
  };
  Enigmail.msg.toggleSmimeToolbar(event);


}

function getEncryptionEnabled_test(){



  Enigmail.msg.juniorMode = true;
  let ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    return {
      getUnicharAttribute : function(){
        return "xyz";
      }
    };
  };

  Enigmail.msg.juniorMode = false;
  ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, true);

  getCurrentIdentity = function(){
    return {
      getUnicharAttribute : function(){
        return "";
      }
    };
  };

  Enigmail.msg.isEnigmailEnabled = function(){
    return true;
  };
  ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = function(){
    return false;
  };
  ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, false);
}

function isSmimeEnabled_test() {

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return "";
      }
    };
  };

  var ret = Enigmail.msg.isSmimeEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return "xyz";
      }
    };
  };

  ret = Enigmail.msg.isSmimeEnabled();
  Assert.equal(ret, true);
}

function getSigningEnabled_test(){

  Enigmail.msg.juniorMode = true;
  let ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return "xyz";
      }
    };
  };

  Enigmail.msg.juniorMode = false;
  ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, true);

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return "";
      }
    };
  };

  Enigmail.msg.isEnigmailEnabled = function(){
    //Function Overriding
    return true;
  };
  ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = function(){
    return false;
  };
  ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, false);

}

function getSmimeSigningEnabled_test(){
  Enigmail.msg.juniorMode = true;
  let ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return false;
      }
    };
  };

  ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getUnicharAttribute : function(){
        return true;
      },
      getBoolAttribute : function(){
        return false;
      }
    };
  };

  ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

}

function setOwnKeyStatus_test(){

  Enigmail.msg.allowAttachOwnKey = function(){
    //Function Overriding
    return 0;
  };

  document.getElementById = function(str){
    return {
      setAttribute : function(){
        Assert.ok(true);
      },
      removeAttribute : function(){
        Assert.ok(true);
      }
    };
  };

  Enigmail.msg.setOwnKeyStatus();
  Assert.equal(Enigmail.msg.statusAttachOwnKey, EnigmailLocale.getString("attachOwnKeyDisabled"));

  Enigmail.msg.allowAttachOwnKey = function(){
    //Function Overriding
    return 1;
  };

  Enigmail.msg.attachOwnKeyObj.appendAttachment = true;
  Enigmail.msg.setOwnKeyStatus();
  Assert.equal(Enigmail.msg.statusAttachOwnKey, EnigmailLocale.getString("attachOwnKeyYes"));

  Enigmail.msg.attachOwnKeyObj.appendAttachment = false;
  Enigmail.msg.setOwnKeyStatus();
  Assert.equal(Enigmail.msg.statusAttachOwnKey, EnigmailLocale.getString("attachOwnKeyNo"));
}

function processAccountSpecificDefaultOptions_test(){

  Enigmail.msg.sendMode = 0;
  Enigmail.msg.sendPgpMime = "";

  Enigmail.msg.getSmimeSigningEnabled = function(){
    //Function Overriding
    return true;
  };

  Enigmail.msg.isEnigmailEnabled = function(){
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 1);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, "");

  Enigmail.msg.isEnigmailEnabled = function(){
    //Function Overriding
    return true;
  };

  Enigmail.msg.getAccDefault = function(){
    //Function Overriding
    return true;
  };

  Enigmail.msg.setOwnKeyStatus = function(){
    //Function Overriding
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 3);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

  Enigmail.msg.getAccDefault = function(){
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 1);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);

  Enigmail.msg.getSmimeSigningEnabled = function(){
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 0);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);

  Enigmail.msg.reasonSigned = "";

  Enigmail.msg.getAccDefault = function(str){
    //Function Overriding
    if(str === "sign"){
      return false;
    }
    else{
      return true;
    }
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 2);
  Assert.equal(Enigmail.msg.reasonSigned, "");
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("reasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

}

function delayedProcessFinalState_test(){

  Enigmail.msg.processFinalState = function(){
    //Function Overriding
    Assert.ok(true);
  };
  Enigmail.msg.updateStatusBar = function(){
    //Function Overriding
    Assert.ok(true);
  };

  EnigmailTimer.setTimeout = function(callback, val){
    //Function Overriding
    Assert.equal(val, 100);
    callback();
  };

  Enigmail.msg.delayedProcessFinalState();

}

function handleClick_test(){

  let event = {
    button : 2,
    preventDefault : function(){
      Assert.ok(true);
    }
  };

  Enigmail.msg.doPgpButton = function(str){
    //Function Overriding
    Assert.ok(true);
  };

  let modifyType = "xyz";

  Enigmail.msg.handleClick(event, modifyType);

  event = {
    button : 0,
    preventDefault : function(){
      Assert.ok(true);
    }
  };

  Enigmail.msg.doPgpButton = function(str){
    //Function Overriding
    Assert.equal(str, "xyz");
    Assert.ok(true);
  };

  Enigmail.msg.handleClick(event, modifyType);
}

function setIdentityDefaults_test(){


  Enigmail.msg.processAccountSpecificDefaultOptions = function(){
    //Function Overriding
  };

  Enigmail.msg.determineSendFlags = function(){
    //Function Overriding
  };

  Enigmail.msg.processFinalState = function(){
    //Function Overriding
  };

  Enigmail.msg.updateStatusBar = function(){
    //Function Overriding
  };

  EnigmailFuncs = {
    //Function Overriding
    getSignMsg : function(){
      Assert.ok(true);
    }
  };

  Enigmail.msg.isEnigmailEnabled = function() {
    //Function Overriding
    return true;
  };

  Enigmail.msg.juniorMode = false;
  Enigmail.msg.sendModeDirty = true;

  getCurrentIdentity = function(){
    //Function Overriding
    return {
      getIntAttribute : function(){
        return true;
      }
    };
  };

  Enigmail.msg.setIdentityDefaults();

  Enigmail.msg.isEnigmailEnabled = function() {
    //Function Overriding
    return false;
  };

  Enigmail.msg.setIdentityDefaults();

  Assert.equal(Enigmail.msg.statusEncryptedStr, EnigmailLocale.getString("encryptNo"));
  Assert.equal(Enigmail.msg.statusSignedStr, EnigmailLocale.getString("signNo", [""]));
  Assert.equal(Enigmail.msg.statusPGPMimeStr, EnigmailLocale.getString("pgpmimeNormal"));
  Assert.equal(Enigmail.msg.statusInlinePGPStr, EnigmailLocale.getString("inlinePGPNormal"));
  Assert.equal(Enigmail.msg.statusSMimeStr, EnigmailLocale.getString("smimeNormal"));
  Assert.equal(Enigmail.msg.statusAttachOwnKey, EnigmailLocale.getString("attachOwnKeyNo"));

  Enigmail.msg.juniorMode = true;

  Enigmail.msg.pepEnabled = function(){
    //Function Overriding
    return false;
  };

  document = {
    getElementById : function(){
      return {
        setAttribute : function(str1, bool){
          Assert.equal(bool, "false");
        }
      };
    }
  };

  Enigmail.msg.setIdentityDefaults();

  Enigmail.msg.pepEnabled = function(){
    //Function Overriding
    return true;
  };

  document = {
    getElementById : function(){
      return {
        setAttribute : function(str1, bool){
          Assert.equal(bool, "true");
        }
      };
    }
  };

  Enigmail.msg.setIdentityDefaults();

  Enigmail.msg.sendModeDirty = false;
  Enigmail.msg.setIdentityDefaults();

  Enigmail.msg.statusEncryptedStr = "";
  Enigmail.msg.statusSignedStr = "";
  Enigmail.msg.statusPGPMimeStr = "";
  Enigmail.msg.statusInlinePGPStr = "";
  Enigmail.msg.statusSMimeStr = "";
  Enigmail.msg.statusAttachOwnKey = "";

}

function getOriginalMsgUri_test(){
  gMsgCompose = {
    compFields : {
      draftId : 'HelloWorld\s'
    }
  };

  let ret = Enigmail.msg.getOriginalMsgUri();
  Assert.equal(ret, "HelloWorlds");

  gMsgCompose = {
    compFields : {
      draftId : ''
    },
    originalMsgURI : "xyz"
  };

  ret = Enigmail.msg.getOriginalMsgUri();
  Assert.equal(ret, "xyz");

}

function getMsgHdr_test(){
  //Check for Only Null
  Enigmail.msg.getOriginalMsgUri = function(){
    return null;
  };

  let ret = Enigmail.msg.getMsgHdr(null);
  Assert.equal(ret, null);

}

function initialSendFlags_test(){

  Enigmail.msg.fireSendFlags = function(){
    Assert.ok(true);
  };

  Enigmail.msg.determineSendFlags = function(){
    Assert.ok(true);
  };

  Enigmail.msg.processFinalState = function(){
    Assert.ok(true);
  };

  Enigmail.msg.updateStatusBar = function(){
    Assert.ok(true);
  };

  EnigmailTimer.setTimeout = function(){
    Assert.ok(true);
  };

  Enigmail.msg.initialSendFlags();
}

function getOriginalPepMsgRating_test(){

  Enigmail.msg.getOriginalMsgUri = function(){
    return null;
  };

  Enigmail.msg.getMsgHdr = function(){
    return null;
  };

  Enigmail.msg.getOriginalPepMsgRating();
  Assert.equal(Enigmail.msg.origPepRating, null);

  Enigmail.msg.getMsgHdr = function(){
    return {
      getUint32Property : function(){
        return 0xFFF;
      }
    };
  };

  Enigmail.msg.getOriginalPepMsgRating();
  Assert.equal(Enigmail.msg.origPepRating, 15);

  Enigmail.msg.getMsgHdr = function(){
    return {
      getUint32Property : function(){
        return 0xF6;
      }
    };
  };

  Enigmail.msg.getOriginalPepMsgRating();
  Assert.equal(Enigmail.msg.origPepRating, 0);
}

function setDraftStatus_test(){

  Enigmail.msg.encryptForced = 1;
  Enigmail.msg.signForced = 2;
  Enigmail.msg.pgpmimeForced = 3;
  Enigmail.msg.protectHeaders = 4;
  Enigmail.msg.attachOwnKeyObj = {
    appendAttachment : 1
  };

  Enigmail.msg.setAdditionalHeader = function(str, draftStatus){
    Assert.equal(str, "X-Enigmail-Draft-Status");
    Assert.equal(draftStatus, "N12311");
  };

  Enigmail.msg.setDraftStatus(1);


  Enigmail.msg.pgpmimeForced = 0;
  Enigmail.msg.protectHeaders = 4;
  Enigmail.msg.attachOwnKeyObj = {
    appendAttachment : null
  };

  Enigmail.msg.setAdditionalHeader = function(str, draftStatus){
    Assert.equal(str, "X-Enigmail-Draft-Status");
    Assert.equal(draftStatus, "N12000");
  };

  Enigmail.msg.setDraftStatus(0);
}

function fireSendFlags_test(){

  Enigmail.msg.determineSendFlags = function(){
    Assert.ok(true);
  };

  Enigmail.msg.fireSearchKeys = function(){
    Assert.ok(true);
  };

  EnigmailTimer.setTimeout = function(callback, time){
    callback();
    Assert.ok(true);
    return null;
  };

  Enigmail.msg.determineSendFlagId = false;

  Enigmail.msg.fireSendFlags();

  Assert.equal(Enigmail.msg.determineSendFlagId, null);
}

function getMailPref_test(){
  EnigmailPrefs.getPrefRoot = function(){
    return {
      getPrefType : function(){
        return true;
      },
      getBoolPref : function(str){
        Assert.ok(true);
        Assert.equal(str, 'xyz');
      },
      PREF_BOOL : true
    };
  };

  Enigmail.msg.getMailPref('xyz');

  EnigmailPrefs.getPrefRoot = function(){
    return {
      getPrefType : function(){
        return true;
      },
      getIntPref : function(str){
        Assert.ok(true);
        Assert.equal(str, 'xyz');
      },
      PREF_INT : 1
    };
  };

  Enigmail.msg.getMailPref('xyz');

  EnigmailPrefs.getPrefRoot = function(){
    return {
      getPrefType : function(){
        return true;
      },
      getCharPref : function(str){
        Assert.ok(true);
        Assert.equal(str, 'xyz');
      },
      PREF_STRING : 'str'
    };
  };

  Enigmail.msg.getMailPref('xyz');

}

function setAdditionalHeader_test(){
  gMsgCompose = {
    compFields : {
      setHeader : function(){
        Assert.ok(true);
      }
    }
  };

  Enigmail.msg.setAdditionalHeader('hdr', 'val');

  gMsgCompose = {
    compFields : {
      otherRandomHeaders : 'hello'
    }
  };

  Enigmail.msg.setAdditionalHeader('hdr', 'val');

  Assert.equal(gMsgCompose.compFields.otherRandomHeaders, 'hellohdr: val\r\n');
}

function unsetAdditionalHeader_test(){
  gMsgCompose = {
    compFields : {
      deleteHeader : function(){
        Assert.ok(true);
      }
    }
  };

  Enigmail.msg.unsetAdditionalHeader('hdr');

  gMsgCompose = {
    compFields : {
      otherRandomHeaders : 'hello'
    }
  };

  Enigmail.msg.unsetAdditionalHeader('hdr: hello\r\n');

  Assert.equal(gMsgCompose.compFields.otherRandomHeaders, 'hello');
}

function modifyCompFields_test(){
  getCurrentIdentity = function(){
    Assert.ok(true);
    return true;
  };

  EnigmailApp = {
    getVersion : function(){
      Assert.ok(true);
    }
  };

  Enigmail.msg.setAdditionalHeader = function(){
    Assert.ok(true);
  };

  Enigmail.msg.isEnigmailEnabled = function(){
    Assert.ok(true);
  };

  EnigmailPrefs.getPref = function(){
    Assert.ok(true);
    return true;
  };

  Enigmail.msg.modifyCompFields();
}

function getCurrentIncomingServer_test(){
  getCurrentAccountKey = function(){
    return true;
  };

  MailServices = {
    accounts : {
      getAccount : function(currentAccountKey){
        Assert.equal(currentAccountKey, true);
        return {
          incomingServer : true
        };
      }
    }
  };

  let ret = Enigmail.msg.getCurrentIncomingServer();
  Assert.equal(ret, true);
}

function fireSearchKeys_test(){

  Enigmail.msg.isEnigmailEnabled = function(){
    return true;
  };

  Enigmail.msg.searchKeysTimeout = true;

  Enigmail.msg.fireSearchKeys();
  Assert.equal(Enigmail.msg.searchKeysTimeout, true);

  Enigmail.msg.searchKeysTimeout = false;

  Enigmail.msg.findMissingKeys = function(){
    Assert.ok(true);
  };

  EnigmailTimer.setTimeout = function(callback, time){
    Assert.ok(true);
    Assert(time, 5000);
    callback();
    Assert.equal(Enigmail.msg.searchKeysTimeout, null);
    return false;
  };

  Enigmail.msg.fireSearchKeys();
  Assert.equal(Enigmail.msg.searchKeysTimeout, false);
}

function focusChange_test() {
  CommandUpdate_MsgCompose = function(){
    Assert.ok(true);
  };

  Enigmail.msg.lastFocusedWindow = true;

  top = {
    document : {
      commandDispatcher : {
        focusedWindow : true
      }
    }
  };

  Enigmail.msg.focusChange();
  Assert.equal(Enigmail.msg.lastFocusedWindow, true);

  Enigmail.msg.lastFocusedWindow = false;

  Enigmail.msg.fireSendFlags = function(){
    Assert.ok(true);
  };

  Enigmail.msg.focusChange();
  Assert.equal(Enigmail.msg.lastFocusedWindow, true);

}

function addressOnChange_test(){

  Enigmail.msg.addrOnChangeTimer = false;
  Enigmail.msg.fireSendFlags = function(){
    Assert.ok(true);
  };
  EnigmailTimer.setTimeout = function(callback, time){
    Assert.equal(time, 250);
    callback();
    Assert.equal(Enigmail.msg.addrOnChangeTimer, null);
    return true;
  };

  Enigmail.msg.addressOnChange();

  Assert.equal(Enigmail.msg.addrOnChangeTimer, true);
}

function editorGetContentAs_test(){
  Enigmail.msg.editor = {
    outputToString : function(mimeType, flags){
      Assert.equal(mimeType, 'mime');
      Assert.equal(flags, 'flags');
      return true;
    }
  };

  let ret = Enigmail.msg.editorGetContentAs('mime', 'flags');
  Assert.equal(ret, true);

  Enigmail.msg.editor = false;
  ret = Enigmail.msg.editorGetContentAs('mime', 'flags');
  Assert.equal(ret, null);

}

function editorGetCharset_test(){

  Enigmail.msg.editor = {
    documentCharacterSet: 'xyz'
  };

  Enigmail.msg.editorGetCharset();
  Assert.equal(Enigmail.msg.editor.documentCharacterSet, 'xyz');
}

function editorSelectAll_test(){
  Enigmail.msg.editor = {
    selectAll : function(){
      Assert.ok(true);
    }
  };
  Enigmail.msg.editorSelectAll();
}

function displayPartialEncryptedWarning_test(){

  Enigmail.msg.notifyUser = function(priority, msgText, messageId, detailsText){
    Assert.equal(priority, 1);
    Assert.equal(detailsText, EnigmailLocale.getString("msgCompose.partiallyEncrypted.inlinePGP"));
    Assert.equal(msgText, EnigmailLocale.getString("msgCompose.partiallyEncrypted.short"));
    Assert.equal(messageId, "notifyPartialDecrypt");
  };

  Enigmail.msg.displayPartialEncryptedWarning();
}

function setChecked_test(){
  document = {
    getElementById : function(){
      return {
        setAttribute : function(str, bool){
          Assert.ok(true);
          Assert.ok(str, "checked");
          Assert.ok(bool, "true");
        },
        removeAttribute : function(str){
          Assert.ok(true);
          Assert.ok(str, "checked");
        }
      };
    }
  };

  Enigmail.msg.setChecked('id', true);

  Enigmail.msg.setChecked('id', false);

}

function pepEnabled_test(){
  getCurrentIdentity = function(){
    return {
      getBoolAttribute : function(str){
        Assert.ok(true);
        Assert.ok(str, "enablePEP");
      }
    };
  };

  Enigmail.msg.pepEnabled();
}

function attachOwnKey_test(){

  Enigmail.msg.attachOwnKeyObj.attachedKey = 'xy';
  Enigmail.msg.identity = {
    getIntAttribute : function(){
      return 1;
    },
    getCharAttribute : function(){
      return 'xyz';
    }
  };

  Enigmail.msg.removeAttachedKey = function(){
    Assert.ok(true);
  };

  Enigmail.msg.attachOwnKey();

  Enigmail.msg.removeAttachedKey = function(){
    Assert.ok(false);
  };

  Enigmail.msg.attachOwnKeyObj.attachedKey = 'xyz';
  Enigmail.msg.attachOwnKey();

  Enigmail.msg.attachOwnKeyObj.attachedKey = null;

  Enigmail.msg.extractAndAttachKey = function(){
    return 'key';
  };

  Enigmail.msg.attachOwnKey();
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, 'key');
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, 'xyz');

  Enigmail.msg.attachOwnKeyObj.attachedObj = null;
  Enigmail.msg.attachOwnKeyObj.attachedKey = null;
  Enigmail.msg.extractAndAttachKey = function(){
    return null;
  };
  Enigmail.msg.attachOwnKey();
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);

}

function attachKey_test(){
  window.openDialog = function(xulFilePath, str1, options, inputObj, resultObj){
    Assert.equal(xulFilePath, "chrome://enigmail/content/ui/enigmailKeySelection.xul");
    Assert.equal(str1, '');
    Assert.equal(options, "dialog,modal,centerscreen,resizable");
    Assert.equal(inputObj.options, "multisel,allowexpired,nosending");
    Assert.equal(inputObj.dialogHeader, EnigmailLocale.getString("keysToExport"));
  };

  Enigmail.msg.extractAndAttachKey = function(){
    Assert.ok(true);
  };

  Enigmail.msg.trustAllKeys = false;

  Enigmail.msg.attachKey();

  window.openDialog = function(xulFilePath, str1, options, inputObj, resultObj){
    Assert.equal(inputObj.options, "multisel,allowexpired,nosending,trustallkeys");
  };

  Enigmail.msg.trustAllKeys = true;

  Enigmail.msg.attachKey();
}

function addAttachment_test(){

  AddAttachments = function(att){
    Assert.equal(att[0], 'xyz');
  };

  Enigmail.msg.addAttachment('xyz');

  AddAttachment = function(att){
    Assert.equal(att, 'xyz');
  };

  Enigmail.msg.addAttachment('xyz');
}

function enableUndoEncryption_test(){

  document.getElementById = function(){
    return {
      removeAttribute : function(){
        Assert.ok(true);
      },
      setAttribute : function(){
        Assert.ok(true);
      }
    };
  };

  Enigmail.msg.enableUndoEncryption(true);

  Enigmail.msg.enableUndoEncryption(false);

}

function resetUpdatedFields_test(){

  gMsgCompose = {
    compFields : {
      securityInfo : 'xyz'
    }
  };

  Enigmail.msg.removeAttachedKey = function(){
    Assert.ok(true);
  };

  EnigmailMsgCompFields.isEnigmailCompField = function(val){
    Assert.equal(val, 'xyz');
    return true;
  };

  EnigmailMsgCompFields.getValue = function(si, subject) {
    Assert.equal(si, 'xyz');
    Assert.equal(subject, 'originalSubject');
    return 'subject';
  };

  Enigmail.msg.resetUpdatedFields();
  Assert.equal(gMsgCompose.compFields.subject, 'subject');


}

function sendAborted_test(){

  EnigmailDialog = {
    info : function(){
      Assert.ok(true);
    }
  };
  Enigmail.msg.sendAborted(window, null);

  let errorMsgObj = {
    value : 'INV_RECP 10 key10\nINV_SGNR 1 key1\nINV_RECP 4 key4\nINV_SGNR 5 key5'
  };

  EnigmailDialog.info = function(window, val){
      Assert.equal(val, "Send operation aborted.\n\nNot enough trust for key 'key10'\nKey 'key1' not found\nKey 'key4' revoked\nKey 'key5' expired\n\nINV_RECP 10 key10\nINV_SGNR 1 key1\nINV_RECP 4 key4\nINV_SGNR 5 key5");
  };

  Enigmail.msg.sendAborted(window, errorMsgObj);

  errorMsgObj = {
    value : 'INV_RECP 10 key10'
  };

  EnigmailDialog.info = function(window, val){
    Assert.equal(val, "Send operation aborted.\n\nNot enough trust for key 'key10'\n\nINV_RECP 10 key10");
  };

  Enigmail.msg.sendAborted(window, errorMsgObj);

  errorMsgObj = {
    value : 'INV_RECP 10 key10\nI_SGNR 1 key1\nINV_RECP 4 key4\nINV_SGNR 5 key5'
  };

  EnigmailDialog.info = function(window, val){
    Assert.equal(val, "Send operation aborted.\n\nNot enough trust for key 'key10'\nKey 'key4' revoked\nKey 'key5' expired\n\nINV_RECP 10 key10\nI_SGNR 1 key1\nINV_RECP 4 key4\nINV_SGNR 5 key5");
  };

  Enigmail.msg.sendAborted(window, errorMsgObj);

  errorMsgObj = {
    value : 'INV_RECP10key10'
  };

  EnigmailDialog.info = function(window, val){
    Assert.equal(val, "Send operation aborted.\n\nINV_RECP10key10");
  };

  Enigmail.msg.sendAborted(window, errorMsgObj);

}

function checkProtectHeaders_test(){

  let ret = Enigmail.msg.checkProtectHeaders(0x0080);
  Assert.equal(ret, true);

  ret = Enigmail.msg.checkProtectHeaders(0x0082);
  Assert.equal(ret, true);

  ret = Enigmail.msg.checkProtectHeaders(0x0002);
  Assert.equal(ret, true);

  Enigmail.msg.protectHeaders = true;

  ret = Enigmail.msg.checkProtectHeaders(0x0082);
  Assert.equal(ret, true);

  Enigmail.msg.protectHeaders = false;

  EnigmailDialog.msgBox = function(){
    return -1;
  };

  EnigmailPrefs.getPref = function(){
    return 1;
  };

  ret = Enigmail.msg.checkProtectHeaders(0x0082);
  Assert.equal(ret, false);

  Enigmail.msg.protectHeaders = false;

  EnigmailDialog.msgBox = function(){
    Assert.ok(true);
    return 0;
  };

  Enigmail.msg.displayProtectHeadersStatus = function(){
    Assert.ok(true);
  };

  EnigmailPrefs.setPref = function(prop, val){
    Assert.equal(val, 2);
  };

  ret = Enigmail.msg.checkProtectHeaders(0x0082);
  Assert.equal(ret, true);
  Assert.equal(Enigmail.msg.protectHeaders, true);

  Enigmail.msg.protectHeaders = false;
  
  EnigmailDialog.msgBox = function(){
    return -2;
  };

  Enigmail.msg.displayProtectHeadersStatus = function(){
    Assert.ok(true);
  };

  EnigmailPrefs.setPref = function(prop, val){
    Assert.equal(val, 0);
  };

  ret = Enigmail.msg.checkProtectHeaders(0x00082);
  Assert.equal(ret, true);
  Assert.equal(Enigmail.msg.protectHeaders, false);

}

function attachPepKey_test(){

  Enigmail.msg.identity = {
    getBoolAttribute : function(){
      Assert.ok(true);
      return true;
    }
  };

  EnigmailPEPAdapter.getOwnIdentityForEmail = function(){
    Assert.ok(true);
    return null;
  };

  Enigmail.msg.attachPepKey();

  EnigmailPEPAdapter.getOwnIdentityForEmail = function(){
    Assert.ok(true);
    return {
      fpr : "001"
    };
  };

  Enigmail.msg.attachOwnKeyObj.attachedKey = "0x002";

  Enigmail.msg.removeAttachedKey = function(){
    Assert.ok(true);
    Enigmail.msg.attachOwnKeyObj.attachedKey = null;
  };

  Enigmail.msg.extractAndAttachKey = function(){
    Assert.ok(true);
    return {
      name : ''
    };
  };

  gMsgCompose.compFields.addAttachment = function(attachedObj){
    Assert.ok(true);
    Assert.equal(attachedObj.name, "pEpkey.asc");
  };

  Enigmail.msg.attachPepKey();
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj.name, "pEpkey.asc");
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, "0x001");
}

function createEnigmailSecurityFields_test(){

  gMsgCompose.compFields.securityInfo = '';
  EnigmailMsgCompFields.createObject = function(){
    Assert.ok(true);
    return 'secureInformation';
  };

  Enigmail.msg.createEnigmailSecurityFields();
  Assert.equal(gMsgCompose.compFields.securityInfo, 'secureInformation');

}

function getPepMessageRating_test(){

  Enigmail.msg.pepEnabled = function(){
    return false;
  };

  Enigmail.msg.setPepPrivacyLabel = function(val){
    Assert.ok(true);
    Assert.equal(val, 0);
  };

  Enigmail.msg.getPepMessageRating();

  Enigmail.msg.pepEnabled = function(){
    return true;
  };

  Enigmail.msg.compileFromAndTo = function(){
    return null;
  };

  Enigmail.msg.setPepPrivacyLabel = function(val){
    Assert.equal(val, 0);
  };

  Enigmail.msg.getPepMessageRating();
  Assert.equal(Enigmail.msg.determineSendFlagId, null);

  Enigmail.msg.compileFromAndTo = function(){
    return 'arrOfAddr';
  };

  EnigmailPEPAdapter.getOutgoingMessageRating = function(){
    return 5;
  };

  Enigmail.msg.setPepPrivacyLabel = function(val){
    Assert.equal(val, 5);
  };

  Enigmail.msg.getPepMessageRating();
  Assert.equal(Enigmail.msg.determineSendFlagId, null);
}

function compileFromAndTo_test(){
  Enigmail.msg.composeBodyReady = {};

  gMsgCompose.expandMailingLists = function(){
    Assert.ok(true);
  };

  Recipients2CompFields = function(){
    Assert.ok(true);
  };

  gMsgCompose.compFields = {
    to : ['user1@enigmail.net','user2@enigmail.net'],
    cc : ['user3@enigmail.net','user4@enigmail.net'],
    bcc : ['user5@enigmail.net','user6@enigmail.net']
  };

  getCurrentIdentity = function(){
    Assert.ok(true);
    return {
      email : 'user@enigmail.net',
      fullName : 'User Name'
    };
  };

  EnigmailFuncs.parseEmails = function(emailAddr){
    Assert.ok(true);
    return [
      {
        email : emailAddr[0]
      }, {
        email : emailAddr[1]
      }
    ];
  };

  let ret = Enigmail.msg.compileFromAndTo();
  Assert.equal(ret.from.email, 'user@enigmail.net');
  Assert.equal(ret.from.name, 'User Name');
  Assert.equal(ret.toAddrList.length, 6);

  gMsgCompose.compFields = {
    to : ['user1@enigmail.net','user2@enigmail.net'],
    cc : ['user3@enigmail.net','user4@enigmail.net'],
    bcc : ['user5@enigmail.net','user6.enigmail.net']
  };

  ret = Enigmail.msg.compileFromAndTo();
  Assert.equal(ret, null);

}

function setPepPrivacyLabel_test(){
  document.getElementById = function(){
    return {
      getAttribute : function(){
        return "false";
      },
      setAttribute : function(prop, val){
        if(prop === "value"){
          Assert.equal(val, EnigmailLocale.getString("msgCompose.pepSendUnsecure"));
        }
        else if(prop === "class"){
          Assert.equal(val, "enigmail-statusbar-pep-unsecure");
        }
      }
    };
  };

  EnigmailPEPAdapter.calculateColorFromRating = function(){
    return "green";
  };

  Enigmail.msg.setPepPrivacyLabel(1);

  document.getElementById = function(){
    return {
      getAttribute : function(){
        return "true";
      },
      setAttribute : function(prop, val){
        if(prop === "value"){
          Assert.equal(val, EnigmailLocale.getString("msgCompose.pepSendUnknown"));
        }
        else if(prop === "class"){
          Assert.equal(val, "enigmail-statusbar-pep-unsecure");
        }
      }
    };
  };

  Enigmail.msg.setPepPrivacyLabel(0);

  document.getElementById = function(){
    return {
      getAttribute : function(){
        return "true";
      },
      setAttribute : function(prop, val){
        if(prop === "value"){
          Assert.equal(val, EnigmailLocale.getString("msgCompose.pepSendTrusted"));
        }
        else if(prop === "class"){
          Assert.equal(val, "enigmail-statusbar-pep-trusted");
        }
      }
    };
  };

  Enigmail.msg.setPepPrivacyLabel(1);

  EnigmailPEPAdapter.calculateColorFromRating = function(){
    return "yellow";
  };

  document.getElementById = function(){
    return {
      getAttribute : function(){
        return "true";
      },
      setAttribute : function(prop, val){
        if(prop === "value"){
          Assert.equal(val, EnigmailLocale.getString("msgCompose.pepSendSecure"));
        }
        else if(prop === "class"){
          Assert.equal(val, "enigmail-statusbar-pep-secure");
        }
      }
    };
  };

  Enigmail.msg.setPepPrivacyLabel(1);
}

function isSendConfirmationRequired_test(){
  EnigmailPrefs.getPref = function(){
    return 0;
  };

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_SMIME;

  let ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function(){
    return 1;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function(){
    return 2;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function(){
    return 2;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function(){
    return 3;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function(){
    return 3;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function(){
    return 4;
  };

  Enigmail.msg.sendMode = 0x0001;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  Enigmail.msg.sendMode = 0x0002;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  Enigmail.msg.statusPGPMime = null;
  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_YES;

  EnigmailDialog.confirmDlg = function(){
    return false;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, null);

  Enigmail.msg.statusPGPMime = null;
  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_YES;

  EnigmailDialog.confirmDlg = function(){
    return true;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_FORCEYES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = null;
  Enigmail.msg.statusEncryptedInStatusBar = EnigmailConstants.ENIG_FINAL_YES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = null;
  Enigmail.msg.statusEncryptedInStatusBar = EnigmailConstants.ENIG_FINAL_FORCEYES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

}

function isSmimeEncryptionPossible_test(){

  getCurrentIdentity = function(){
    return {
      getUnicharAttribute : function(){
        return "";
      }
    };
  };

  let ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    return {
      getUnicharAttribute : function(){
        return "string";
      }
    };
  };

  gMsgCompose.compFields = {
    hasRecipients : false
  };

  ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, false);

  getCurrentIdentity = function(){
    return {
      getUnicharAttribute : function(){
        return "string";
      }
    };
  };

  gMsgCompose.compFields = {
    hasRecipients : true
  };

  ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, true);

}

function preferPgpOverSmime_test(){
  gMsgCompose.compFields.securityInfo = Components.classes["@mozilla.org/messenger-smime/composefields;1"].createInstance();

  let ret = Enigmail.msg.preferPgpOverSmime(0x0001);
  Assert.equal(ret, 1);

  gMsgCompose.compFields.securityInfo.requireEncryptMessage = 1;

  Enigmail.msg.mimePreferOpenPGP = 2;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 0);

  gMsgCompose.compFields.securityInfo.requireEncryptMessage = 0;
  gMsgCompose.compFields.securityInfo.signMessage = 1;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 0);

  gMsgCompose.compFields.securityInfo.signMessage = 0;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 1);

  gMsgCompose.compFields.securityInfo.signMessage = 1;

  ret = Enigmail.msg.preferPgpOverSmime(0x0003);
  Assert.equal(ret, 2);

}

function displaySecuritySettings_test(){

  Enigmail.msg.processFinalState = function(){
    Assert.ok(true);
  };

  Enigmail.msg.updateStatusBar = function(){
    Assert.ok(true);
  };

  window.openDialog = function(windowURL, str1, prop, param){
    param.resetDefaults = true;
  };

  Enigmail.msg.encryptForced = null;
  Enigmail.msg.signForced = null;
  Enigmail.msg.pgpmimeForced = null;
  Enigmail.msg.finalSignDependsOnEncrypt = null;

  Enigmail.msg.displaySecuritySettings();
  Assert.equal(Enigmail.msg.encryptForced, null);
  Assert.equal(Enigmail.msg.signForced, null);
  Assert.equal(Enigmail.msg.pgpmimeForced, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, null);

  window.openDialog = function(windowURL, str1, prop, param){
    param.resetDefaults = true;
    param.success = true;
  };

  Enigmail.msg.displaySecuritySettings();
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

  window.openDialog = function(windowURL, str1, prop, param){
    param.resetDefaults = false;
    param.success = true;
    param.sign = 1;
    param.encrypt = 2;
    param.pgpmime = 3;
  };

  Enigmail.msg.signForced = null;

  Enigmail.msg.displaySecuritySettings();
  Assert.equal(Enigmail.msg.dirty, 2);
  Assert.equal(Enigmail.msg.signForced, 1);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);
  Assert.equal(Enigmail.msg.encryptForced, 2);
  Assert.equal(Enigmail.msg.pgpmimeForced, 3);

  Enigmail.msg.signForced = 1;
  Enigmail.msg.encryptForced = 1;
  Enigmail.msg.dirty = null;

  Enigmail.msg.displaySecuritySettings();
  Assert.equal(Enigmail.msg.dirty, 2);
}

function onPepHandshakeButton_test(){

  Enigmail.msg.pepEnabled = function(){
    return false;
  };

  Enigmail.msg.pepDisabledError = function(){
    Assert.ok(true);
  };

  Enigmail.msg.onPepHandshakeButton();

  let event = {
    stopPropagation : function(){
      Assert.ok(true);
    }
  };

  document.getElementById = function(){
    return "false";
  };

  EnigmailDialog.info = function(window, prop){
    Assert.equal(prop, EnigmailLocale.getString("handshakeDlg.error.noProtection"));
  };

  Enigmail.msg.onPepHandshakeButton();

  Enigmail.msg.compileFromAndTo = function(){
    Assert.ok(true);
    return {
      toAddrList : []
    };
  };

  EnigmailFuncs.stripEmail = function(){
    Assert.ok(true);
    return {};
  };

  EnigmailDialog.info = function(window, val){
    Assert.equal(val, EnigmailLocale.getString("handshakeDlg.error.noPeers"));
  };

  Enigmail.msg.onPepHandshakeButton();

  Enigmail.msg.compileFromAndTo = function(){
    Assert.ok(true);
    return {
      toAddrList : ["user1@enigmail.net", "user2@enigmail.net"]
    };
  };

  EnigmailFuncs.stripEmail = function(){
    Assert.ok(true);
    return "user1@enigmail.net,user2@enigmail.net";
  };

  getCurrentIdentity = function(){
    return {
      email : 'user@enigmail.net'
    };
  };

  Enigmail.msg.getPepMessageRating.bind = function(){
    return true;
  };

  window.openDialog = function(windowURL, str1, prop, param){
    Assert.equal(param.myself, 'user@enigmail.net');
    Assert.equal(param.addresses.length, 2);
    Assert.equal(param.direction, 1);
    Assert.equal(param.onComplete, true);
  };

  Enigmail.msg.onPepHandshakeButton();

}

function pepMenuPopup_test(){

  document.getElementById = function(prop){
    if(prop === "enigmail_compose_pep_encrypt"){
      return {
        setAttribute : function(prop, val){
          if(prop === "checked"){
            Assert.equal(val, "false");
          }
          else{
            Assert.equal(prop, "disabled");
            Assert.equal(val, "true");
          }
        },
        removeAttribute : function(prop){
          Assert.equal(prop, "disabled");
        }
      };
    }
    else if(prop === "enigmail_composeMenu_pep_handshake"){
      return {
        setAttribute : function(prop, val){
          Assert.ok(prop, "disabled");
          Assert.ok(val, "true");
        },
        removeAttribute : function(prop){
          Assert.equal(prop, "disabled");
        }
      };
    }
    else if(prop === "enigmail-bc-pepEncrypt"){
      return {
        getAttribute : function(){
          Assert.ok(true);
          return "false";
        }
      };
    }

    return {};
  };

  Enigmail.msg.pepEnabled = function(){
    return true;
  };

  Enigmail.msg.pepMenuPopup();

  Enigmail.msg.pepEnabled = function(){
    return false;
  };

  Enigmail.msg.pepMenuPopup();

}

function pepDisabledError_test(){

  EnigmailDialog.alert = function(window, val){
    Assert.equal(val, EnigmailLocale.getString("pep.alert.disabledForIdentity"));
  };

  Enigmail.msg.pepDisabledError();

}

function onPepEncryptMenu_test(){

  Enigmail.msg.pepEnabled = function(){
    Assert.ok(true);
    return false;
  };

  Enigmail.msg.pepDisabledError = function(){
    Assert.ok(true);
  };

  Enigmail.msg.onPepEncryptMenu();

  Enigmail.msg.pepEnabled = function(){
    Assert.ok(true);
    return true;
  };

  Enigmail.msg.getPepMessageRating = function(){
    Assert.ok(true);
  };

  document.getElementById = function(){
    return {
      setAttribute : function(prop, val){
        Assert.equal(prop, "encrypt");
        Assert.equal(val, "false");
      },
      getAttribute : function () {
        return "true";
      }
    };
  };

  Enigmail.msg.onPepEncryptMenu();

  document.getElementById = function(){
    return {
      setAttribute : function(prop, val){
        Assert.equal(prop, "encrypt");
        Assert.equal(val, "true");
      },
      getAttribute : function () {
        return "false";
      }
    };
  };

  Enigmail.msg.onPepEncryptMenu();

}

function onPepEncryptButton_test(){

  Enigmail.msg.onPepEncryptMenu = function(){
    Assert.ok(true);
  };

  Enigmail.msg.onPepEncryptButton();
}

function getForceRecipientDlg_test(){
  EnigmailPrefs.getPref = function(prop){
    if(prop === "assignKeysByRules"){
      return true;
    }
    else if(prop === "assignKeysByEmailAddr"){
      return false;
    }
    else if(prop === "assignKeysManuallyIfMissing"){
      return false;
    }

    return false;
  };

  let ret = Enigmail.msg.getForceRecipientDlg();
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function(prop){
    if(prop === "assignKeysByRules"){
      return true;
    }
    else if(prop === "assignKeysByEmailAddr"){
      return true;
    }
    else if(prop === "assignKeysManuallyIfMissing"){
      return false;
    }

    return false;
  };

  ret = Enigmail.msg.getForceRecipientDlg();
  Assert.equal(ret, false);
}

function addRecipients_test(){
  let recList = [
    "user1@enigmail.net,",
    "user2@enigmail.net,"
  ];

  let addrList = [];

  EnigmailFuncs.stripEmail = function(val){
    return val;
  };

  Enigmail.msg.addRecipients(addrList, recList);
  Assert.equal(addrList.length, 2);
  Assert.equal(addrList[0], 'user1@enigmail.net');
  Assert.equal(addrList[1], 'user2@enigmail.net');

}

function editorInsertAsQuotation_test(){

  Enigmail.msg.editor = null;
  let ret = Enigmail.msg.editorInsertAsQuotation();
  Assert.equal(ret, 0);

  Enigmail.msg.editor = {};
  ret = Enigmail.msg.editorInsertAsQuotation();
  Assert.equal(ret, 0);

  // Enigmail.msg.editor = Components.classes["@mozilla.org/editor/texteditor;1"].createInstance();
  // ret = Enigmail.msg.editorInsertAsQuotation(null);
  // Assert.equal(ret, 1);
}

function allowAttachOwnKey_test(){

  Enigmail.msg.isEnigmailEnabled = function(){
    return false;
  };
  let ret = Enigmail.msg.allowAttachOwnKey();
  Assert.equal(ret, -1);

  Enigmail.msg.isEnigmailEnabled = function(){
    return true;
  };

  Enigmail.msg.identity.getIntAttribute = function(){
    return 0;
  };
  ret = Enigmail.msg.allowAttachOwnKey();
  Assert.equal(ret, 0);

  Enigmail.msg.identity.getIntAttribute = function(){
    return 2;
  };

  Enigmail.msg.identity.getCharAttribute = function(){
    return 'xyz';
  };
  ret = Enigmail.msg.allowAttachOwnKey();
  Assert.equal(ret, 0);

  Enigmail.msg.identity.getCharAttribute = function(){
    return '02';
  };
  ret = Enigmail.msg.allowAttachOwnKey();
  Assert.equal(ret, 1);

}

function displaySMimeToolbar_test(){
  document.getElementById = function() {
    return {
      removeAttribute : function(){
        Assert.ok(true);
      }
    };
  };

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_SMIME;
  Enigmail.msg.displaySMimeToolbar();

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_FORCESMIME;
  Enigmail.msg.displaySMimeToolbar();

  Enigmail.msg.statusPGPMime = null;
  document.getElementById = function() {
    return {
      setAttribute : function(){
        Assert.ok(true);
      }
    };
  };

  Enigmail.msg.displaySMimeToolbar();

}

function replaceEditorText_test(){
  Enigmail.msg.editorSelectAll = function(){
    Assert.ok(true);
  };

  Enigmail.msg.editorInsertText = function(val){
    Assert.ok(true);
    if(val === "Enigmail" || val === "text"){
      Assert.ok(true);
    }
    else{
      Assert.ok(false);
    }
  };

  Enigmail.msg.editor.textLength = 4;

  Enigmail.msg.replaceEditorText("text");

  Enigmail.msg.editor.textLength = 0;
  Enigmail.msg.editorInsertText = function(val){
    Assert.ok(true);
    if(val === " " || val === "text"){
      Assert.ok(true);
    }
    else{
      Assert.ok(false);
    }
  };
}

function getMsgFolderFromUri_test(){

  MailUtils.getFolderForURI = function(uri, checkFolderAttributes){
    return uri;
  };

  let ret = Enigmail.msg.getMsgFolderFromUri('uri', 'attr');
  Assert.equal(ret, 'uri');

  GetResourceFromUri = function(){
    return {
      QueryInterface : function(){
        return {
          name : 'Folder Name',
          isServer : false
        };
      }
    };
  };

  MailUtils = undefined;

  ret = Enigmail.msg.getMsgFolderFromUri('uri', 'attr');
  Assert.equal(ret, null);

  ret = Enigmail.msg.getMsgFolderFromUri('uri', null);
  Assert.equal(ret.name, 'Folder Name');

}

function isEnigmailEnabled_test(){

  Enigmail.msg.juniorMode = true;
  let ret = Enigmail.msg.isEnigmailEnabled();
  Assert.equal(ret, false);

  Enigmail.msg.juniorMode = false;
  Enigmail.msg.identity = {
    getBoolAttribute : function(){
      Assert.ok(true);
      return true;
    }
  };
  ret = Enigmail.msg.isEnigmailEnabled();
  Assert.equal(ret, true);

}

function isAutocryptEnabled_test(){

  Enigmail.msg.isEnigmailEnabled = function(){
    return false;
  };

  let ret = Enigmail.msg.isAutocryptEnabled();
  Assert.equal(ret, false);

  Enigmail.msg.isEnigmailEnabled = function(){
    return true;
  };

  Enigmail.msg.getCurrentIncomingServer = function(){
    return {
      getBoolValue : function(){
        return true;
      }
    };
  };

  ret = Enigmail.msg.isAutocryptEnabled();
  Assert.equal(ret, true);

  Enigmail.msg.getCurrentIncomingServer = function(){
    return {
      getBoolValue : function(){
        return false;
      }
    };
  };

  ret = Enigmail.msg.isAutocryptEnabled();
  Assert.equal(ret, false);

  Enigmail.msg.getCurrentIncomingServer = function(){
    return null;
  };

  ret = Enigmail.msg.isAutocryptEnabled();
  Assert.equal(ret, false);

}

function goAccountManager_test(){

  EnigmailCore.getService = function(){
    Assert.ok(true);
  };

  getCurrentIdentity = function(){
    return 'id';
  };

  EnigmailFuncs.getAccountForIdentity = function(){
    return 'account';
  };

  window.openDialog = function(xulPath, str1, prop, param){
    Assert.equal(param.identity, 'id');
    Assert.equal(param.account, 'account');
  };

  Enigmail.msg.setIdentityDefaults = function(){
    Assert.ok(true);
  };

  Enigmail.msg.goAccountManager();
}

function displayProtectHeadersStatus_test(){
  document.getElementById = function(){
    return {
      setAttribute : function(prop, val){
        if(prop === "checked"){
          Assert.equal(val, "true");
        }
        else if(prop === "tooltiptext"){
          Assert.equal(val, EnigmailLocale.getString("msgCompose.protectSubject.tooltip"));
        }
      }
    };
  };

  this.protectHeaders = [];

  Enigmail.msg.displayProtectHeadersStatus();

  document.getElementById = function(){
    return {
      setAttribute : function(prop, val){
        Assert.equal(val, EnigmailLocale.getString("msgCompose.noSubjectProtection.tooltip"));
        Assert.equal(prop, "tooltiptext");
      },
      removeAttribute : function(prop){
        Assert.equal(prop, "checked");
      }
    };
  };

  this.protectHeaders = null;

  Enigmail.msg.displayProtectHeadersStatus();
}

function msgComposeReset_test(){
  Enigmail.msg.setIdentityDefaults = function(){
    Assert.ok(false);
  };

  Enigmail.msg.msgComposeReset(true);
  Assert.equal(Enigmail.msg.dirty, 0);
  Assert.equal(Enigmail.msg.processed, null);
  Assert.equal(Enigmail.msg.timeoutId, null);
  Assert.equal(Enigmail.msg.modifiedAttach, null);
  Assert.equal(Enigmail.msg.sendMode, 0);
  Assert.equal(Enigmail.msg.sendModeDirty, false);
  Assert.equal(Enigmail.msg.reasonEncrypted, "");
  Assert.equal(Enigmail.msg.reasonSigned, "");
  Assert.equal(Enigmail.msg.encryptByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.signByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.pgpmimeByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusEncryptedStr, "???");
  Assert.equal(Enigmail.msg.statusSignedStr, "???");
  Assert.equal(Enigmail.msg.statusPGPMimeStr, "???");
  Assert.equal(Enigmail.msg.statusInlinePGPStr, "???");
  Assert.equal(Enigmail.msg.statusAttachOwnKey, "???");
  Assert.equal(Enigmail.msg.enableRules, true);
  Assert.equal(Enigmail.msg.identity, null);
  Assert.equal(Enigmail.msg.sendProcess, false);
  Assert.equal(Enigmail.msg.trustAllKeys, false);
  Assert.equal(Enigmail.msg.mimePreferOpenPGP, 0);
  Assert.equal(Enigmail.msg.origPepRating, null);
  Assert.equal(Enigmail.msg.keyLookupDone.length, 0);

  Enigmail.msg.setIdentityDefaults = function(){
    Assert.ok(true);
  };

  Enigmail.msg.msgComposeReset(false);
}

function initRadioMenu_test(){

  EnigmailPrefs.getPref = function(prefName){
    Assert.equal(prefName, 'prefName');
    return 1;
  };

  document.getElementById = function(){
    Assert.ok(false);
  };

  Enigmail.msg.initRadioMenu('prefName', ['option1']);

  EnigmailPrefs.getPref = function(prefName){
    Assert.equal(prefName, 'prefName');
    return 1;
  };

  document.getElementById = function(val){
    Assert.equal(val, 'enigmail_option2');
    return {
      setAttribute : function(prop, val){
        Assert.equal(prop, "checked");
        Assert.equal(val, "true");
      }
    };
  };

  Enigmail.msg.initRadioMenu('prefName', ['option1', 'option2']);
}

function toggleAttachOwnKey_test(){

  EnigmailCore.getService = function(){
    Assert.ok(true);
  };

  Enigmail.msg.attachOwnKeyObj.appendAttachment = true;

  Enigmail.msg.setOwnKeyStatus = function(){
    Assert.ok(true);
  };

  Enigmail.msg.toggleAttachOwnKey();
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);

}

function toggleProtectHeaders_test(){
  EnigmailCore.getService = function(){
    Assert.ok(true);
  };

  Enigmail.msg.protectHeaders = true;

  Enigmail.msg.displayProtectHeadersStatus = function(){
    Assert.ok(true);
  };

  Enigmail.msg.toggleProtectHeaders();
  Assert.equal(Enigmail.msg.protectHeaders, false);
}


function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");
  do_load_module("chrome://enigmail/content/modules/constants.jsm");
  do_load_module("chrome://enigmail/content/modules/locale.jsm");

  pepEnabled_test();
  isEnigmailEnabled_test();
  pepDisabledError_test();
  isSmimeEncryptionPossible_test();
  isSmimeEnabled_test();
  getAccDefault_test();
  trustAllKeys_test();
  processFinalState_test();
  setFinalSendMode_test();
  signingNoLongerDependsOnEnc_test();
  toggleSMimeEncrypt_test();
  toggleSMimeSign_test();
  tryEnablingSMime_test();
  setSendMode_test();
  toggleAccountAttr_test();
  toggleAttribute_test();
  fixMessageSubject_test();
  notifyUser_test();
  toggleSmimeToolbar_test();
  getEncryptionEnabled_test();
  getSigningEnabled_test();
  getSmimeSigningEnabled_test();
  allowAttachOwnKey_test();
  setOwnKeyStatus_test();
  processAccountSpecificDefaultOptions_test();
  delayedProcessFinalState_test();
  handleClick_test();
  setIdentityDefaults_test();
  setIdentityCallback_test();
  getOriginalMsgUri_test();
  getMsgHdr_test();
  fireSendFlags_test();
  initialSendFlags_test();
  getOriginalPepMsgRating_test();
  setAdditionalHeader_test();
  unsetAdditionalHeader_test();
  setDraftStatus_test();
  getMailPref_test();
  modifyCompFields_test();
  getCurrentIncomingServer_test();
  fireSearchKeys_test();
  focusChange_test();
  addressOnChange_test();
  editorGetContentAs_test();
  editorGetCharset_test();
  editorSelectAll_test();
  displayPartialEncryptedWarning_test();
  setChecked_test();
  attachOwnKey_test();
  attachKey_test();
  addAttachment_test();
  enableUndoEncryption_test();
  resetUpdatedFields_test();
  sendAborted_test();
  checkProtectHeaders_test();
  attachPepKey_test();
  createEnigmailSecurityFields_test();
  compileFromAndTo_test();
  setPepPrivacyLabel_test();
  getPepMessageRating_test();
  isSendConfirmationRequired_test();
  preferPgpOverSmime_test();
  displaySecuritySettings_test();
  onPepHandshakeButton_test();
  pepMenuPopup_test();
  onPepEncryptMenu_test();
  onPepEncryptButton_test();
  getForceRecipientDlg_test();
  addRecipients_test();
  editorInsertAsQuotation_test();
  displaySMimeToolbar_test();
  replaceEditorText_test();
  getMsgFolderFromUri_test();
  goAccountManager_test();
  displayProtectHeadersStatus_test();
  msgComposeReset_test();
  initRadioMenu_test();
  toggleAttachOwnKey_test();
  toggleProtectHeaders_test();
}

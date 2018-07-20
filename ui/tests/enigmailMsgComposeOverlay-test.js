/*global Enigmail: false, Assert: false, do_load_module: false, trustAllKeys_test: false, JSUnit: false, Components: false, EnigmailConstants: false, EnigmailLocale: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


var window;
var document;

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

function processFinalState_test() {
  // Encryption Status and Reason

  // //Overriding Functions
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;
  // var isSmimeEnabled = Enigmail.msg.isSmimeEnabled;
  // var getAccDefault = Enigmail.msg.getAccDefault;

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

  // //Uoverriding Functions
  // Enigmail.msg.isEnigmailEnabled = isEnigmailEnabled;
  // Enigmail.msg.isSmimeEnabled = isSmimeEnabled;
  // Enigmail.msg.getAccDefault = getAccDefault;

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

  // var determineSendFlags = Enigmail.msg.determineSendFlags;

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

  // Enigmail.msg.determineSendFlags = determineSendFlags;

}

function signingNoLongerDependsOnEnc_test() {
  Enigmail.msg.finalSignDependsOnEncrypt = true;
  Enigmail.msg.juniorMode = true;
  Enigmail.msg.signingNoLongerDependsOnEnc();
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

  Enigmail.msg.juniorMode = false;
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

  // //Overriding Functions
  // var isSmimeEncryptionPossible = Enigmail.msg.isSmimeEncryptionPossible;

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

  // //Overriding Functions
  // Enigmail.msg.isSmimeEncryptionPossible = isSmimeEncryptionPossible;

}

function setSendMode_test() {

  // //Overrding Functions
  // var updateStatusBar = Enigmail.msg.updateStatusBar;
  // var processFinalState = Enigmail.msg.processFinalState;

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

  // //Unoverrding Functions
  // Enigmail.msg.updateStatusBar = updateStatusBar;
  // Enigmail.msg.processFinalState = processFinalState;

}


function getAccDefault_test() {

  // //Overriding Functions
  // var isSmimeEnabled = Enigmail.msg.isSmimeEnabled;
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;
  // var getAccDefault = Enigmail.msg.getAccDefault;

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

  // //Unoverriding Functions
  // Enigmail.msg.isSmimeEnabled = isSmimeEnabled;
  // Enigmail.msg.isEnigmailEnabled = isEnigmailEnabled;
  // Enigmail.msg.getAccDefault = getAccDefault;

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

  // //Overriding Functions
  // var setIdentityDefaults = Enigmail.msg.setIdentityDefaults;

  Enigmail.msg.setIdentityDefaults = function(){
    //Function Overriding
    Assert.ok(true);
  };

  Enigmail.msg.setIdentityCallback('xyz');

  // //Unoverriding Functions
  // Enigmail.msg.setIdentityDefaults = setIdentityDefaults;
}

function toggleSmimeToolbar_test(){

  //Overriding Functions
  var toggleSMimeSign = Enigmail.msg.toggleSMimeSign;
  var toggleSMimeEncrypt = Enigmail.msg.toggleSMimeEncrypt;

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

  // //Unoverriding Functions
  // Enigmail.msg.toggleSMimeSign = toggleSMimeSign;
  // Enigmail.msg.toggleSMimeEncrypt = toggleSMimeEncrypt;

}

function getEncryptionEnabled_test(){

  // //Overriding Functions
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;

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

  // //Unoverriding Functions
  // Enigmail.msg.isEnigmailEnabled = isEnigmailEnabled;
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

  // //Overriding following Functions
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;

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

  // //Unoverriding Function
  // isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;

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

  // //Overriding following Functions
  // var allowAttachOwnKey = Enigmail.msg.allowAttachOwnKey;

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

  // //Unoverriding Function
  // Enigmail.msg.allowAttachOwnKey = allowAttachOwnKey;
}

function processAccountSpecificDefaultOptions_test(){

  // //Overriding following Functions
  // var getSmimeSigningEnabled = Enigmail.msg.getSmimeSigningEnabled;
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;
  // var getAccDefault = Enigmail.msg.getAccDefault;
  // var setOwnKeyStatus = Enigmail.msg.setOwnKeyStatus;

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

  // //Unoverriding Function
  // Enigmail.msg.getSmimeSigningEnabled = getSmimeSigningEnabled;
  // Enigmail.msg.isEnigmailEnabled = isEnigmailEnabled;
  // Enigmail.msg.getAccDefault = getAccDefault;
  // Enigmail.msg.setOwnKeyStatus = setOwnKeyStatus;

}

function delayedProcessFinalState_test(){

  // //Overriding following Functions
  // var processFinalState = Enigmail.msg.processFinalState;
  // var updateStatusBar = Enigmail.msg.updateStatusBar;
  // var setTimeout = EnigmailTimer.setTimeout;

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

  // //Unoverriding Function
  // Enigmail.msg.processFinalState = processFinalState;
  // EnigmailTimer.setTimeout = setTimeout;
  // Enigmail.msg.updateStatusBar = updateStatusBar;

}

function handleClick_test(){

  // //Overriding following Functions
  // var doPgpButton = Enigmail.msg.doPgpButton;

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

  // //Unoverriding Function
  // Enigmail.msg.doPgpButton = doPgpButton;
}

function setIdentityDefaults_test(){

  // //Overriding following Functions
  // var processAccountSpecificDefaultOptions = Enigmail.msg.processAccountSpecificDefaultOptions;
  // var determineSendFlags = Enigmail.msg.determineSendFlags;
  // var processFinalState = Enigmail.msg.processFinalState;
  // var updateStatusBar = Enigmail.msg.updateStatusBar;
  // var isEnigmailEnabled = Enigmail.msg.isEnigmailEnabled;
  // var pepEnabled = Enigmail.msg.pepEnabled;


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

  // //Unoverriding Function
  // Enigmail.msg.processAccountSpecificDefaultOptions = processAccountSpecificDefaultOptions;
  // Enigmail.msg.determineSendFlags = determineSendFlags;
  // Enigmail.msg.processFinalState = processFinalState;
  // Enigmail.msg.updateStatusBar = updateStatusBar;
  // Enigmail.msg.isEnigmailEnabled = isEnigmailEnabled;
  // Enigmail.msg.pepEnabled = pepEnabled;

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

function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");
  do_load_module("chrome://enigmail/content/modules/constants.jsm");
  do_load_module("chrome://enigmail/content/modules/locale.jsm");

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
  setOwnKeyStatus_test();
  processAccountSpecificDefaultOptions_test();
  delayedProcessFinalState_test();
  handleClick_test();
  setIdentityDefaults_test();
  setIdentityCallback_test();
  getOriginalMsgUri_test();
  getMsgHdr_test();
  initialSendFlags_test();
  getOriginalPepMsgRating_test();
}

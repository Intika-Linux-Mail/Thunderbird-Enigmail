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
    return null;
  };

  Enigmail.msg.updateStatusBar = () => {
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

  Enigmail.msg.isSmimeEnabled = () => {
    return true;
  };

  Enigmail.msg.isEnigmailEnabled = () => {
    return true;
  };

  Enigmail.msg.identity = {};

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return false;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
    return 0;
  };

  let ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  Enigmail.msg.identity.getIntAttribute = (key) => {
    return 1;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return true;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
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
    return 0;
  };

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('random');
  Assert.equal(ret, false);

  Enigmail.msg.isSmimeEnabled = () => {
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

  let attr_name = 'random';
  Enigmail.msg.identity.getBoolAttribute = function(){
    return true;
  };

  Enigmail.msg.identity.setBoolAttribute = function(attrName, oldValue){
    Assert.equal(attrName, attr_name);
    Assert.equal(oldValue, false);
  };

  Enigmail.msg.toggleAccountAttr(attr_name);

}

function toggleAttribute_test(){

  let attr_name = 'random';
  EnigmailPrefs.getPref = function(){
    return true;
  };

  EnigmailPrefs.setPref = function(attrName, oldValue){
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


function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");
  do_load_module("chrome://enigmail/content/modules/constants.jsm");
  do_load_module("chrome://enigmail/content/modules/locale.jsm");

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

}

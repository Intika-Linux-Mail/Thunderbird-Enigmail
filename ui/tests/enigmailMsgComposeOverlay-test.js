/*global Enigmail: false, Assert: false, do_load_module: false, trustAllKeys_test: false, JSUnit: false, Components: false, EnigmailConstants: false, EnigmailLocale: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


var window;
var document;

var gSMFields;

function trustAllKeys_test() {
  // test functionality of trustAllKeys
  Enigmail.msg.trustAllKeys = true;
  Enigmail.msg.tempTrustAllKeys();
  Assert.equal(Enigmail.msg.trustAllKeys, false, "check trustAllKeys is false");

  Enigmail.msg.tempTrustAllKeys();
  Assert.equal(Enigmail.msg.trustAllKeys, true, "check trustAllKeys is true");

}

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

function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");
  do_load_module("chrome://enigmail/content/modules/constants.jsm");
  do_load_module("chrome://enigmail/content/modules/locale.jsm");

  trustAllKeys_test();
  processFinalState_test();
  setFinalSendMode_test();
  signingNoLongerDependsOnEnc_test();
  toggleSMimeEncrypt_test();
  toggleSMimeSign_test();
}

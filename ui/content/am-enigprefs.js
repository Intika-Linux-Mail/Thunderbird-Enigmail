/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* global Components: false, gIdentity: true, gAccount: true */

"use strict";

Components.utils.import("resource://enigmail/pEpAdapter.jsm"); /*global EnigmailPEPAdapter: false */
Components.utils.import("resource://enigmail/log.jsm"); /*global EnigmailLog: false */
Components.utils.import("resource://enigmail/core.jsm"); /*global EnigmailCore: false */
Components.utils.import("resource://enigmail/overlays.jsm"); /*global EnigmailOverlays: false */

if (!Enigmail) var Enigmail = {};

var gPref = null;
var gUsingPep = null;

function onInit() {
  EnigmailLog.DEBUG("am-enigprefs.js: onInit()\n");
  Enigmail.overlayInitialized = true;

  if (Enigmail.overlayLoaded) performInit();
}

function performInit() {
  EnigmailLog.DEBUG("am-enigprefs.js: performInit()\n");

  gUsingPep = EnigmailPEPAdapter.usingPep();
  Enigmail.edit.onInit();
}

function onAcceptEditor() {
  EnigmailLog.DEBUG("am-enigprefs.js: onAcceptEditor()\n");
  Enigmail.edit.onSave();
  saveChanges();
  return true;
}

function onPreInit(account, accountValues) {
  EnigmailLog.DEBUG("am-enigprefs.js: onPreInit()\n");

  Enigmail.overlayLoaded = false;
  Enigmail.overlayInitialized = false;

  if (!EnigmailCore.getService()) {
    return;
  }

  let foundEnigmail = document.getElementById("enigmail_enablePgp");

  if (!foundEnigmail) {
    // Enigmail Overlay not yet loaded
    EnigmailOverlays.insertXul("enigmailEditIdentity.xul", window, document,
      function _cb() {
        EnigmailLog.DEBUG("am-enigprefs.js: onPreInit: XUL inserted\n");

        Enigmail.edit.identity = account.defaultIdentity;
        Enigmail.edit.account = account;
        Enigmail.overlayLoaded = true;

        try {
          if (Enigmail.overlayInitialized) performInit();
        }
        catch (ex) {
          EnigmailLog.DEBUG(`am-enigprefs.js: onPreInit: error: ${ex.message}\n${ex.stack}\n`);
        }
      });
  }
  else {
    // Enigmail Overlay already loaded
    Enigmail.edit.identity = account.defaultIdentity;
    Enigmail.edit.account = account;
    Enigmail.overlayLoaded = true;
  }
}

function onSave() {
  EnigmailLog.DEBUG("am-enigprefs.js: onSave()\n");

  Enigmail.edit.onSave();
  saveChanges();
  return true;
}

function onLockPreference() {
  // do nothing
}

// Does the work of disabling an element given the array which contains xul id/prefstring pairs.
// Also saves the id/locked state in an array so that other areas of the code can avoid
// stomping on the disabled state indiscriminately.
function disableIfLocked(prefstrArray) {
  // do nothing
}

function enigmailOnAcceptEditor() {
  EnigmailLog.DEBUG("am-enigprefs.js: enigmailOnAcceptEditor()\n");

  Enigmail.edit.onSave();

  return true; // allow to close dialog in all cases
}


function saveChanges() {}

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";
/*
  Wrapper file that is inclued for every Test executed
*/

const JSUnit = ChromeUtils.import("chrome://enigmail/content/jsunit/jsunit-main.jsm").JSUnit;

var Assert = JSUnit.assert;

// create placeholders for window and document to be used by command
// line tests
//
// an empty document is always available; window is only created on request


function do_get_file(filename, allowNonexistent) {
  var c = Components.stack.caller;
  return JSUnit.getFile(c, filename, allowNonexistent);
}

var do_get_cwd = JSUnit.getCwd;

var do_test_pending = JSUnit.testPending;

var do_test_finished = JSUnit.testFinished;

var do_print = JSUnit.printMsg;

function do_subtest(filePath) {
  JSUnit.printMsg("*** Executing sub-test '" + filePath + "' ***");
  return JSUnit.executeScript(filePath);
}


function do_load_module(urlString, targetObj) {
  /* eslint no-invalid-this: 0 */
  if (targetObj) {
    JSUnit.loadScript(urlString, targetObj);
  } else {
    JSUnit.loadScript(urlString, this);
  }
}

function do_open_tinyjsd() {}

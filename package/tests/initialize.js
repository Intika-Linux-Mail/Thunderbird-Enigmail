/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, do_test_pending: false, do_test_finished: false, component: false */
/*global EnigmailCore: false, EnigmailFiles: false, EnigmailLog: false, EnigmailPrefs: false */
/*global setupTestAccounts: false, setupTestAccount: false, getCurrentTime: true */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

try {
  let cwd = do_get_cwd();
  cwd.append("testHelper.js");
  do_load_module("file://" + cwd.path); /*global TestHelper: false, addMacPaths: false, withEnigmail: false, withTestGpgHome: false*/
  TestHelper.loadDirectly("tests/mailHelper.js"); /*global MailHelper: false */
  MailHelper.deleteAllAccounts();
}
catch (x) {
  /* global do_print: false */
  do_print("Initialize Error: " + x.message + "\n" + x.stack);
  throw x;
}

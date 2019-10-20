/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

/*
  Wrapper file that is inclued for every Test executed
*/
/* global run_test: false, JSUnit: false */

try {
  run_test();
}
catch (ex) {

  JSUnit.abortPendingTests();
  JSUnit.logTestResult("RuntimeError: Caught unhandled exception: " + ex.toString(),
    null,
    ex.fileName +
    " ::  :: line " + ex.lineNumber);

  JSUnit.printMsg("Stack: " + ex.stack);

}

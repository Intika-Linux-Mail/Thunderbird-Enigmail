/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * Default pref values for JSUnit
 */

 /* global pref: false */

"use strict";

// the configured version
pref("extensions.jsunit.configuredVersion", "0.1");

// enable dumping results to the command line
pref("browser.dom.window.dump.enabled", true);

// disable XUL cache
pref("nglayout.debug.disable_xul_cache", true);


pref('javascript.options.showInConsole', true);
pref('devtools.chrome.enabled', true);
pref('extensions.logging.enabled', true);
pref('nglayout.debug.disable_xul_fastload', true);
pref('dom.report_all_js_exceptions', true);
pref('devtools.errorconsole.deprecation_warnings', true);
pref('devtools.errorconsole.enabled', true);

pref('browser.cache.disk.enable', false);
pref('browser.cache.memory.enable', false);
pref('browser.cache.disk.max_entry_size', 0);
pref('browser.cache.memory.max_entry_size', 0);
pref('network.http.use-cache', false);

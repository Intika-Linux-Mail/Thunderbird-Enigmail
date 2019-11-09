#!/usr/bin/env bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

export PL_PATH=`which perl`
export TB_PATH=${TB_PATH:-`which thunderbird`}

if [ `id -u` -eq 0 ]; then
  echo "Warning: Running the test suite as root may cause some tests to fail."
fi

util/run-tests.py "$@"


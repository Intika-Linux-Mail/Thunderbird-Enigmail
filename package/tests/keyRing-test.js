/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, */
/*global Components: false, resetting: false, JSUnit: false, do_test_pending: false, do_test_finished: false, component: false, Cc: false, Ci: false */
/*jshint -W097 */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* eslint no-useless-concat: 0*/
"use strict";

/*global EnigmailFiles: false */
do_load_module("file://" + do_get_cwd().path + "/testHelper.js"); /*global withEnigmail: false, withTestGpgHome: false, getKeyListEntryOfKey: false, gKeyListObj: true, withLogFiles: false */

component("enigmail/trust.jsm"); /*global EnigmailTrust: false */
component("enigmail/locale.jsm"); /*global EnigmailLocale: false */
component("enigmail/log.jsm"); /*global EnigmailLog: false */

/*global getUserIdList: false, createAndSortKeyList: false, Number: false */

testing("keyRing.jsm"); /*global EnigmailKeyRing: false */

test(withTestGpgHome(withEnigmail(function shouldImportFromFileAndGetKeyDetails() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const errorMsgObj = {};
  const importedKeysObj = {};
  const importResult = EnigmailKeyRing.importKeyFromFile(publicKey, errorMsgObj, importedKeysObj);
  Assert.assertContains(importedKeysObj.value, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(importResult, 0, errorMsgObj);
  const keyDetails = EnigmailKeyRing.getValidUids("0xD535623BB60E9E71").join("\n");
  Assert.assertContains(keyDetails, "strike.devtest@gmail.com");
})));

test(withTestGpgHome(withEnigmail(function shouldGetKeyListEntryOfKey() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const importResult = EnigmailKeyRing.importKeyFromFile(publicKey, {}, {});
  const keyDetails = getKeyListEntryOfKey("0xD535623BB60E9E71");


  // Output from GnuPG varies sligtly between different versions (new output data is added
  // at the end of the list). Therefore each line is only compared to the length provided below
  let expectedListing = [
    "pub:-:4096:1:781617319CE311C4:1430756251:::-:::scESC:",
    "fpr:::::::::65537E212DC19025AD38EDB2781617319CE311C4:",
    "uid:-::::1557592308::DB54FB278F6AE719DE0DE881B17D4C762F5752A9::anonymous strike <strike.devtest@gmail.com>:",
    "sub:-:4096:1:D535623BB60E9E71:1430756251::::::e:"
  ];

  let keyDetList = keyDetails.split(/\n\r?/);

  for (let i = 0; i < expectedListing.length; i++) {
    Assert.equal(keyDetList[i].substr(0, expectedListing[i].length), expectedListing[i]);
  }

})));


test(withTestGpgHome(withEnigmail(function shouldGetKeyFunctions() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  EnigmailKeyRing.importKeyFromFile(publicKey, {}, {});
  EnigmailKeyRing.importKeyFromFile(secretKey, {}, {});

  // search for key ID
  let k = EnigmailKeyRing.getKeyById("0x9CE311C4");
  Assert.equal(k.subKeys[0].keyId, "D535623BB60E9E71");

  // search for subkey ID
  k = EnigmailKeyRing.getKeyById("0xD535623BB60E9E71");
  Assert.equal(k.fpr, "65537E212DC19025AD38EDB2781617319CE311C4");

  Assert.equal(gKeyListObj.keySortList.length, 1);
  EnigmailKeyRing.clearCache();
  Assert.equal(gKeyListObj.keySortList.length, 0);

  // search for fingerprint
  k = EnigmailKeyRing.getKeyById("65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(k.fpr, "65537E212DC19025AD38EDB2781617319CE311C4");

  let s = k.signatures;

  let fpr = "DB54FB278F6AE719DE0DE881B17D4C762F5752A9";
  Assert.equal(fpr in s, true);
  if (fpr in s) {
    Assert.equal(s[fpr].sigList[0].signerKeyId, "781617319CE311C4");
  }

  let ka = EnigmailKeyRing.getKeysByUserId("devtest@gmail.com>$");
  Assert.equal(ka.length, 1);

  ka = EnigmailKeyRing.getAllSecretKeys();
  Assert.equal(ka.length, 1);

  ka = EnigmailKeyRing.getKeyListById("0x9CE311C4 D535623BB60E9E71"); // the space is on purpose(!)
  Assert.equal(ka.length, 2);
})));

test(withTestGpgHome(withEnigmail(function shouldGetUserIdList() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  EnigmailKeyRing.importKeyFromFile(publicKey, {}, {});
  EnigmailKeyRing.importKeyFromFile(secretKey, {}, {});
  let l = null;
  l = getUserIdList(false, {}, {}, {});
  Assert.notEqual(l, null);
  l = getUserIdList(true, {}, {}, {});
  Assert.notEqual(l, null);
})));

test(withTestGpgHome(withEnigmail(function shouldCleanupClearCache() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  EnigmailKeyRing.importKeyFromFile(publicKey, {}, {});
  EnigmailKeyRing.importKeyFromFile(secretKey, {}, {});
  EnigmailKeyRing.getAllKeys();
  Assert.notEqual(gKeyListObj.keyList.length, 0);
  EnigmailKeyRing.clearCache();
  Assert.equal(gKeyListObj.keyList.length, 0);
})));

test(withTestGpgHome(withEnigmail(function shouldImportFromTextAndGetKeyDetails() {
  EnigmailKeyRing.importKey(
    JSUnit.createStubWindow(),
    false,
    "-----BEGIN PGP PUBLIC KEY BLOCK-----" +
    "\n" + "" +
    "\n" + "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" +
    "\n" + "J14nd8wqFA==" +
    "\n" + "=Hflu" +
    "\n" + "-----END PGP PUBLIC KEY BLOCK-----" +
    "\n" + "-----BEGIN PGP PRIVATE KEY BLOCK-----" +
    "\n" + "" +
    "\n" + "lQdGBFVHm5sBEACs94Ln+RMdeyBpWQtTZ/NZnwntsB10Wd3HTgo5sdA/OOFOJrWe" +
    "\n" + "tJfAZ/HRxiSu1bwRaFVC8p061ftTbxf8bsdfsykYJQQqPODfcO0/oY2n/Z93ya8K" +
    "\n" + "TzjXR3qBQ1P7f5x71yeuo7Zrj7B0G44Xjfy+1L0eka9paBqmm3U5cUew5wSr772L" +
    "\n" + "cflipWfncWXD2rBqgRfR339lRHd3Vwo7V8jje8rlP9msOuTMWCvQuQvpEkfIioXA" +
    "\n" + "7QipP2f0aPzsavNjFnAfC9rm2FDs6lX4syTMVUWy8IblRYo6MjhNaJFlBJkTCl0b" +
    "\n" + "ugT9Ge0ZUifuAI0ihVGBpMSh4GF2B3ZPidwGSjgx1sojNHzU/3vBa9DuOmW95qrD" +
    "\n" + "Notvz61xYueTpOYK6ZeT880QMDvxXG9S5/H1KJxuOF1jx1DibAn9sfP4gtiQFI3F" +
    "\n" + "WMV9w3YrrqidoWSZBqyBO0Toqt5fNdRyH4ET6HlJAQmFQUbqqnZrc07s/aITZN36" +
    "\n" + "d9eupCZQfW6e80UkXRPCU53vhh0GQey9reDyVCsV7xi6oXk1fqlpDYigQwEr4+yJ" +
    "\n" + "+1qAjtSVHJhFE0inQWkUwc2nxef6n7v/M9HszhP/aABadVE49oDaRm54PtA1l0mC" +
    "\n" + "T8IHcVR4ZDkaNwrHJtidEQcQ/+YVV3g7UJI9+g2nPvgMhk86AzBIlGpG+wARAQAB" +
    "\n" + "/gcDAqej/ZYOzi3Q/yc57TFfSlCcWayO9LTkmpm9VN8nQGAhJ5n/1h8ezRHccB9+" +
    "\n" + "2dYIVks7daTkc072rBRqlMzlxXKkQlRhtRkShX3kb1ypbLc6hRd8AoEkpuOSxBnP" +
    "\n" + "8yXJwTQtFDGGIiGQfhXdJijEgbqo4oEFlSfyVOsHN/dwsjz3DLNlnBn/ZnEJ3kZp" +
    "\n" + "w3XE/d+O4zxdQfmrCFaBzl5W0Hd9Sg42N5lZRX87J+BRSoyLbrI4Z/YoIIFiSJUr" +
    "\n" + "8Flti0P2zeMuLBnOGUuN6NJgtui8wWZ3QT9tq1Nj8D/YwXosCjW/rE+x9p5EIamk" +
    "\n" + "N13R/BNzJUdvmPOo2YrHri1+B2UUeSwlSKB+6UzOGESYpHOHvLSGRhwuPsjB/ZuB" +
    "\n" + "x3nDnLEDmZ9ihDFO1uU5QoDZX1QR0I/1GBTlrwNMnFWkyqfV7L1jzLnHf1lDbl+M" +
    "\n" + "xs6P7aRdHJBfD400CryY58nqWOOvrrMle7B4mykMAhQ8kwXivKECnKoL/PLqYNP+" +
    "\n" + "tyLn5aiWzS+WxzHDhNI7ysQenVSGLej2HatbdbVIi/aum+HMctQ/J4MFd0rmmmIy" +
    "\n" + "k46j99LOGZuWz+rmPA7A5W7NkwrT8tAcLEkkVZVf0NHdnstysFEMJbmluGp5JTwz" +
    "\n" + "V8xDhE3T/nzV3Vpt6PPylfT2SVx2dXUHNBZAmlahyAWLm8tveu+B12czWeWzWp6B" +
    "\n" + "SytyqNY6EJl5nGa+znlIy9k4jpo58QhLixPw9jOvd95IqaR9tigJEbjNOWBjoxrG" +
    "\n" + "9UqyPcG/wzQ0LEYO6Ms5DH3sqKtEJ4OvJnX3DkvQRKQHVJI1wu3bFr9s1PzNaRbt" +
    "\n" + "J0agUUxxbxYw0EHFnS/tmXdo5cbswg7JXeyhyHku8aDfZXJ9qTTwj+mxm1iCDmTm" +
    "\n" + "f2Jxt8R4BLV36sZZ0+nYDFfoxBfh3Z7M55gBcfDKKe1NqOJa3Pf0A+fUhVjD/zf5" +
    "\n" + "xAGkxh1esYrCLUHOtxiu9uyyMwkUpA+G9sf0copFMp8hgjVzA1LLGFk/tx+X1lfk" +
    "\n" + "D68/Ts9N2+jQlChG2mNPeLGoPzMbEztYWcYykA0uqtO0R+qya8FxGqZx8SpQVMor" +
    "\n" + "x8qOFLNGNZ4PLSZsrv5+jTXcLvJ4gMV7qnMcrHaNTvuoxGwWdHLlhi3kcuQKuj+r" +
    "\n" + "WAauHW/E7tjNHhO9CGj59445bm5LkyaUeczaHGv881IQEbqLwwc73IbzIq0uoeqa" +
    "\n" + "VzsJM8FXmxR1/Mmn2uyCxog7FJioBgeKDtQMI0hW/99OVTvG7LtW++QnPbOD1YDw" +
    "\n" + "qt4tX3MTvkq+rVn+0gCcg7c58d+RTb1Y6Hd8x2VYRHu26gzNHDvgJjALPCM7epSC" +
    "\n" + "A2tqaj6bNNqTYZ/iRc/BIIVQ5SodCWvQmoQG86uSSs/yu1iZrFqXoYxHPfTAQmgd" +
    "\n" + "tKR8d68wuJWPBfYjD7osUyN/EXL+XNnF50NsL3RiY79fMWVyQBIB9vswF5ST8mOk" +
    "\n" + "AvZaUlVYssNZ5bpGTXkpwXWWOWogsZo1MJKJ3aNRZD1UhHTBm9JZA2zDomhA0G6U" +
    "\n" + "9p9CosSOMFyQ5QXSVc+7uQ/ZcU4FzghD1riAuVlp7XlXhp5qlMm67X4/MZoYDEIN" +
    "\n" + "s03X2fACnwc4HAbz7qbf8tyNyC113C4wP185A0Y3f5KTj/885A9IyL7KjtDVIXHB" +
    "\n" + "XKThpOmzzc8csWU23oBiSk4noxyX9piwiHBztC8XuOxF/kKfI/wR69f25D4tmfUH" +
    "\n" + "4bjJRpUylZtgfR4i4CmZx/GZ5jefAnw2Rl4M/oPJRav+oPqY6zXx2qG0K2Fub255" +
    "\n" + "bW91cyBzdHJpa2UgPHN0cmlrZS5kZXZ0ZXN0QGdtYWlsLmNvbT6JAk4EEwEKADgC" +
    "\n" + "GwMFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AWIQRlU34hLcGQJa047bJ4FhcxnOMR" +
    "\n" + "xAUCXNb49AAKCRB4FhcxnOMRxMsUEACkSyIlpNoMhDnf1mWwdkTQVy5aWjRu5mFQ" +
    "\n" + "Abpe8vxT4n0lD0HnP2Gls91iJGBolJzE4DiHxXaw09LWfS7WYFpbex11McudRvvk" +
    "\n" + "zCH7UCA2EgPJvIVW2905RXO9w29D4ehAMaB/wqCyoPwGI9q0D6/dH8ElAfTulrvD" +
    "\n" + "qtv13VEdgMZo1ybM/XNSt/zi+ute9b5UZ1TFH2Mzs9qcP2cmRfIWZ4o005Oqrj6h" +
    "\n" + "9htz1rqG6j6u9vrNYAeI+QPQ+HPtwuSeZjagTgzFzRQByECWZn8SVAPFOGrfAWLQ" +
    "\n" + "Osh+JyeOd/XTjhD2NNxWCJgU2vXvWkWkpR4Cyro2f7crdyNWpI1+fca/18goTLo/" +
    "\n" + "hRB2HGXtWQ/Who430Ug09hycd3lAiZQVffSh0Tevu/kL1M08OB9D6eZIoikF2cCe" +
    "\n" + "QlukR9WZDmo5nv3eGgf7DthDGjqKPJiZEH4MQZNeMiK/u7/wmPJckXCPetuWaZzN" +
    "\n" + "hBPdyHZBlD/6QWp/VWmITY5Gk0jlZ9WWi8WAuxK7S5oS5C303Q8n/u2zFVVP6EVl" +
    "\n" + "XnuhLXPlU7nUumQhXjoaEI12WRFOUoYOPeP3ttZyzxRjw7Xbxb8/8IjrsHNRPDm5" +
    "\n" + "NYEHq0Qr7IsGJG6JHIQ+A4WtSziU/+olVuicm2mH01icLYcYPrYzH0ayA2veEv8s" +
    "\n" + "NjJ7DtmyjJ0HRgRVR5ubARAAwV9vG0eUMW6xjVT094zOtCE/pvxkyx+pZuDnGaJg" +
    "\n" + "Ho/16wTnF/9AWLTqqj+w7q/JNAPH3C5GQkgbHtZun73wAqPFW3rp7+CK0k+RYF4e" +
    "\n" + "22D2bHiMuVO159HS6qVVyUajLd1C0v0cMtfF8fI/bFySQwCiKmeDB8IAZJz3ngZw" +
    "\n" + "+GhumyQLgRCOkVuZYWxvFhSXwp4hbkZ4pvlQ+rnH/d8dzZC9E1mNJdD21HVvdrC3" +
    "\n" + "4iqdZ5s/tXUaAXJE+9NbDLNqZOPDuWP7z+jhA8xc4xnQNa/WJG5V4zfVcYUjdNFp" +
    "\n" + "ZnKtQ6hFN+vjKouGCELLhdzX0td/lNpYY5UeR6UcXQzHx4xWJZOYZTrbr6KbHmE5" +
    "\n" + "TMpBZfA+8tKkhSAIqlZeqXZUgVPOGzix6AlBnp7PlJe5tFEocGXVZjInxcP3ycCE" +
    "\n" + "mSPA+bxpDN6xO08axwEPztXyZxmTQUYJ/C452Y0RgP7tX8HqbRWNDcszuZTs01iO" +
    "\n" + "hwSZdYTGr3tpdL7cATy60W20Ycume+wTXxPWtsO2OGhXrIYxKVsRPG0CMjKwRmkW" +
    "\n" + "okNpaV5gOl2GcUPMTlH7LbAEdUzPiW6FyQ7k8PmIWlWtlu2f0c3bTZ2oVggo6bRa" +
    "\n" + "utA7oIC8ABp46+R3LaS4MLy1Sgng31PJ3IcwpC+x4pIdiwu8klEf1czkWoP05I8W" +
    "\n" + "EUcAEQEAAf4HAwI25oIFjb2KSf83GqZT0bDGDDuLAmJDv1MPOMSgLb1gRGWzyeWC" +
    "\n" + "1+KXC/by4JP2zXbaLffFFLHg5Bfv+LHghnXPdZ/NoDKPR0tdnqiqP+9JNhAgOpZl" +
    "\n" + "RP0sL9sNiCWn6Kx5bmMIvOi5yaCabZIbYVwMnx+3jTEgN3SBYa1T92MuqLQP6J5A" +
    "\n" + "kJ2rF/QWx3Q/BOduS3/qjlUDbilDtrMogU9o//Sui/veAK+fjrCMcaq3f4AUKV8A" +
    "\n" + "84E8C3l9OlyqCmM3SWO/69/fu+s+0DhPT67dPJykAoq97x9LfG7GSOk/3WIYXVfT" +
    "\n" + "5Kuf88E0aYIb7BkOSBvz7LtJOWTgnBwSJyWlb6sRMMLb4hWHPehNc4UdXcaBxU4b" +
    "\n" + "BSbtXBHpuLEeoOh4gqVisY901OOUERsFJqt5xe9CciTbwVXqkaU6Ofj0HBfLiUyZ" +
    "\n" + "R6cIYCBEK+C6SfYaUUn98gOGx/b9dtzJM8fyDYdYaC6CS01BvyPglzBOXkCyh9r7" +
    "\n" + "/sMm6JKeMXUNI86BqztfYyLVBgKHE5L88dfgQtUd+morUaK3iBvIrBpFUllDsUcp" +
    "\n" + "03I1kX/8ZFJMqoqHOhzk0gYrJjkV6dvV4w+DrA0nelZjoWvER/Rf5lU5495RI3A1" +
    "\n" + "64DLSPW/N6fyQZnnf0noJjwZBVO0U3q8f2fBWY8EgZrlvxS7K5yVlwFNc/YRLSwx" +
    "\n" + "Qmitt8ZSaUs+J9vBkz1w7xJegSjReb1aGasNg+Rt89RKQQGFwIk0YVZQUcKyLgA2" +
    "\n" + "5xQ1CC2N9z4du+B2Iwb+smq4DJEzg4/fo5ZDqWN165zAToqzmKE2+rR5q5Ix6gqQ" +
    "\n" + "RUwMu/TY/mNwnIOuGMWGZMZ+F0IiwwxgopjMjMqaOmp9pwDlOoTEvvXcWDvBTejX" +
    "\n" + "A+X5efeTOWd+7FgY4KsYV1j07YnxYKvnHvnE6qtl5qi5GFxEbr6L7T1jTG5GJAfS" +
    "\n" + "cBQadQej47UF5lCZz81HN2MhoYDI8MlbvssrQuCQjtg+SHpoxPanoEkANZ9NoSg5" +
    "\n" + "jLztpUD726s0ygBVVasTv/DpdEyrQ4qEiL8RezPwHoKmXg0hCT3ocS567Ye9/SFT" +
    "\n" + "4vxFkbryqYDsiKntA2osbz+eHhjtIIMqNJuyqT/WWwi3HOQ0C/SfDDKAmev3RtWb" +
    "\n" + "HCG4fJnEuSE4pZ3GuBaeIaNjRbb1Hdj57k3Wg2mUC9HEQDGXhSoVPrEl6dLDbNF8" +
    "\n" + "0sNBBjdjmjchidiBaSBiN2WqBRcwq7t5xnr0iRXX4v/N6qPzqkkzojP24Qn2FANS" +
    "\n" + "Lz+pDW/sAsa8hz8Wn67CE9SVVEMfCk64xxA+npmEjBBapP7cbVzw7zOQTCJiVD+M" +
    "\n" + "rKjxJqzppp90VHhdoyF4xfZ+iB9D1ehteGJBIGRpouaQmfxQHhk5/h8UOX3kJTrl" +
    "\n" + "mLfzNlMwUVrxRhREE1ycbne0pkpblvlg5ZuVugbFF7iKLvaJeOz73IPbcRpnFfFt" +
    "\n" + "fsi6jcflDi9ZO9Nm2kPsGZL9yF8dzb/RTY7e9W4m0hXUtTeAWJmpah6Z0Dp1IYU8" +
    "\n" + "wmypqiBqunpX8tZWlDc9a3UDAfp3aN2I1E7wvqf25cD7ZoipVJcOUcE+sfAERsLO" +
    "\n" + "clSAbf4YO94Q1VD5Po+tlULmRWEsxlCZPfg2OSyFFSe2D3Y7N5fztuKfOUbyZjoh" +
    "\n" + "rTHoCMOIeAs/R74/6Rq8f1kRsd7fmlDzhw5X89yccgYv+YfFrJrhkRUo9xNE6aW4" +
    "\n" + "38o3seR1U5lWEr4yogPJ+tglEUamXr50RuFX/e49x1FHUpNCx3ES4B9hQV+myvMZ" +
    "\n" + "iQI2BBgBCgAgAhsMFiEEZVN+IS3BkCWtOO2yeBYXMZzjEcQFAlzW+RkACgkQeBYX" +
    "\n" + "MZzjEcQuWg//Ymxoh29nOGSi9BQT2eZD6wQFpsYV1hCC3GNifzWZ90Hl2wZ3wOzQ" +
    "\n" + "bPL6Yz40ms8/yPnjhCjWdO6Kt+RAERv7/V9yWLutKvgaPeee1tytnLBQMUhsx89R" +
    "\n" + "Mj4mDFW/6fPkft1iu0JVX33OPvJSwmpfrU48AlQprVh7ICodnLWVZnoj/qLye4I3" +
    "\n" + "1XTTuikXHjlNuWcxFqIeLdPyuh5rIXI7cLf+NzZYNxssAECavpY97OS4JtZl3a5L" +
    "\n" + "WVdYrM7u9mgRcR/qouugIz5P5E2mzSezsTXGvufr+kpsIjd//YKFtVci7e8FdmFq" +
    "\n" + "QBPooavOlPnn0bHppfVhYnDjgQy/Yr8FVYuV1MtUUuekJKPNVKJXNZsvxWe+RBq3" +
    "\n" + "aTkVV7fFLrP6DWl+y2Nqyl0gNzcziILZnyc0ZERLD+lLn8Np6WRVgrj1bbbcOSPZ" +
    "\n" + "/hBHLkhr8hERLb/C6VJVCJLCeTPjIcY3uzveFz6h6z6Mynz8ALhcoGs1Rgj722UK" +
    "\n" + "IbB0SrKvd2tk+IEN9haNkkC52N/sId6rdXJ49vR5WvR1bcj3L3Df5wAuSCZG66fE" +
    "\n" + "lfMykmAYsBHLNZ3NzWp9W8qPJtVKePh5QMs+9KDM1B04XWZ6+ZPV5duIdeC5WX5O" +
    "\n" + "OdMo+gr1RYpYR/MMEO1kUs6gIU6eovzfSl1BznM3V3+2bSdeJ3fMKhQ=" +
    "\n" + "=HPTr" +
    "\n" + "-----END PGP PRIVATE KEY BLOCK-----",
    null, {});
  const keyDetails = EnigmailKeyRing.getValidUids("0xD535623BB60E9E71").join("\n");
  Assert.assertContains(keyDetails, "strike.devtest@gmail.com");
  EnigmailKeyRing.getAllKeys();
  Assert.notEqual(gKeyListObj.keyList.length, 0);

  // uses the key listing from shouldGetKeyValidityErrors
  let key = EnigmailKeyRing.getKeyById("D535623BB60E9E71");

  let pubKey = key.getMinimalPubKey("strike.devtest@gmail.com");

  Assert.equal(pubKey.exitCode, 0);

  Assert.equal(pubKey.keyData.substr(0, 192),
    "mQINBFVHm5sBEACs94Ln+RMdeyBpWQtTZ/NZnwntsB10Wd3HTgo5sdA/OOFOJrWe" +
    "tJfAZ/HRxiSu1bwRaFVC8p061ftTbxf8bsdfsykYJQQqPODfcO0/oY2n/Z93ya8K" +
    "TzjXR3qBQ1P7f5x71yeuo7Zrj7B0G44Xjfy+1L0eka9paBqmm3U5cUew5wSr772L");

  Assert.equal(pubKey.keyData.substr(-52),
    "CvVFilhH8wwQ7WRSzqAhTp6i/N9KXUHOczdXf7ZtJ14nd8wqFA==");

  Assert.equal(pubKey.keyData.length, 3020);



})));


test(function shouldCreateKeyListObject() {
  // from: "P:\Program Files (x86)\GNU\GnuPG\pub\gpg2.exe" --charset utf-8 --display-charset utf-8 --batch --no-tty --status-fd 2 --with-fingerprint --fixed-list-mode --with-colons --list-keys
  let keyInfo = [
    // user with trust level "o" (unknown)
    "tru::1:1443339321:1451577200:3:1:5",
    "pub:o:4096:1:DEF9FC808A3FF001:1388513885:1546188604::u:::scaESCA:",
    "fpr:::::::::EA25EF48BF2001E41FAB0C1CDEF9FC808A3FF001:",
    "uid:o::::1389038412::44F73158EF0F47E4595B1FD8EC740519DE24B994::A User ID with CAPITAL letters <user1@enigmail-test.de>:",
    "uid:o::::1389038405::3FC8999BDFF08EF4210026D3F1C064C072517376::A second User ID with CAPITAL letters <user1@enigmail-test.com>:",
    "sub:o:4096:1:E2DEDFFB80C14584:1388513885:1546188604:::::e:"
  ];

  // from: "P:\Program Files (x86)\GNU\GnuPG\pub\gpg2.exe" --charset utf-8 --display-charset utf-8 --batch --no-tty --status-fd 2 --with-fingerprint --fixed-list-mode --with-colons --list-secret-keys
  let secKeyInfo = [
    "sec::4096:1:DEF9FC808A3FF001:1388513885:1546188604:::::::::",
    "fpr:::::::::EA25EF48BF2001E41FAB0C1CDEF9FC808A3FF001:",
    "uid:::::::44F73158EF0F47E4595B1FD8EC740519DE24B994::A User ID with CAPITAL letters <user1@enigmail-test.de>:",
    "uid:::::::3FC8999BDFF08EF4210026D3F1C064C072517376::A second User ID with CAPITAL letters <user1@enigmail-test.com>:",
    "ssb::4096:1:E2DEDFFB80C14584:1388513885::::::::::"
  ];

  createAndSortKeyList(keyInfo, secKeyInfo,
    "validity", // sorted acc. to key validity
    -1); // descending

  let keyListObj = gKeyListObj;
  Assert.notEqual(keyListObj, null);
  Assert.notEqual(keyListObj.keySortList, null);
  Assert.notEqual(keyListObj.keySortList.length, null);
  Assert.equal(keyListObj.keySortList.length, 1);
  Assert.equal(keyListObj.keySortList[0].userId, "a user id with capital letters <user1@enigmail-test.de>");
  Assert.equal(keyListObj.keySortList[0].keyId, "DEF9FC808A3FF001");
  Assert.notEqual(keyListObj.keyList, null);
  Assert.equal(keyListObj.keyList[keyListObj.keySortList[0].keyNum].userId, "A User ID with CAPITAL letters <user1@enigmail-test.de>");

  const TRUSTLEVELS_SORTED = EnigmailTrust.trustLevelsSorted();
  let minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  let details = {};
  let key = EnigmailKeyRing.getValidKeyForRecipient("user1@enigmail-test.de", minTrustLevelIndex, details);
  Assert.notEqual(key, null);
  Assert.equal(key, "DEF9FC808A3FF001");

  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("f");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("user1@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.notEqual(details.msg, null);
});


test(withTestGpgHome(withEnigmail(function shouldExportKey() {
  const publicKey = do_get_file("resources/dev-strike.asc", false);
  const secretKey = do_get_file("resources/dev-strike.sec", false);
  EnigmailKeyRing.importKeyFromFile(publicKey, {}, {});
  EnigmailKeyRing.importKeyFromFile(secretKey, {}, {});
  EnigmailKeyRing.getAllKeys();

  let pub = EnigmailKeyRing.extractKey(false, "0x781617319CE311C4", null, {}, {}).replace(/\r\n/g, "\n");
  Assert.equal(pub.substr(-50), "d8wqFA==\n=Hflu\n-----END PGP PUBLIC KEY BLOCK-----\n");

  let pubAndSec = EnigmailKeyRing.extractKey(true, "strike.devtest@gmail.com", null, {}, {}).replace(/\r\n/g, "\n");
  Assert.equal(pubAndSec.substr(-37), "\n-----END PGP PRIVATE KEY BLOCK-----\n");
  Assert.equal(pubAndSec.split(/\n/).length, 160);
})));



const KeyRingHelper = {
  loadTestKeyList: function() {
    const pkFile = do_get_file("resources/pub-keys.asc", false);
    let publicKeys = EnigmailFiles.readFile(pkFile);
    let rows = publicKeys.split("\n");
    let testKeyList = [];
    for (let i = 0; i < rows.length; ++i) {
      let row = rows[i];
      if (row !== "" && row[0] != "#") {
        testKeyList.push(row);
      }
    }
    createAndSortKeyList(testKeyList, [],
      "validity", // sorted acc. to key validity
      -1); // descending

    let keyListObj = gKeyListObj;
    Assert.notEqual(keyListObj, null);
    Assert.notEqual(keyListObj.keySortList, null);
    Assert.notEqual(keyListObj.keySortList.length, null);
  }
};

test(function testGetValidKeyForOneRecipient() {
  KeyRingHelper.loadTestKeyList();

  const TRUSTLEVELS_SORTED = EnigmailTrust.trustLevelsSorted();
  let minTrustLevelIndex = null;
  let details = null;
  let key = null;

  // unknown key:
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("unknown@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.equal(details.msg, null);
  //Assert.equal(details.msg, "undefined");

  // ordinary full trusted key:
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("f");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("full@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0003AAAA00010001");
  Assert.equal(details.msg, null);
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("full@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0003AAAA00010001");
  Assert.equal(details.msg, null);

  // key not valid for encryption:
  // - no details because it would take time to check details of such a key
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("no-encrypt@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.equal(details.msg, null);

  // disabled key:
  // - no details because it would take time to check details of such a key
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {
    all: ""
  };
  key = EnigmailKeyRing.getValidKeyForRecipient("disabled@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.equal(details.msg, null);

  // multiple non-trusted and one full trusted keys
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("f");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("multiple-onefull@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0030AAAA00020001");
  Assert.equal(details.msg, null);

  // multiple non-trusted and two full trusted keys (first taken)
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("f");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("multiple-twofull@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0034AAAA00020001");
  Assert.equal(details.msg, null);

  // multiple non-trusted and one marginal trusted keys
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("f");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("multiple-onemarginal@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.equal(details.msg, "ProblemNoKey");
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("multiple-onemarginal@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0031AAAA00020001");
  Assert.equal(details.msg, null);

  // multiple non-trusted keys with same trust level
  // (faked keys case if no special trust given)
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("multiple-nofull@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, null);
  Assert.equal(details.msg, "ProblemMultipleKeys");

  // some key with subkey that encrypts:
  // we return first main key
  minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf("?");
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("withsubkey-uid1@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0040EEEE00010001");
  Assert.equal(details.msg, null);
  details = {};
  key = EnigmailKeyRing.getValidKeyForRecipient("withsubkey-uid2@enigmail-test.de", minTrustLevelIndex, details);
  Assert.equal(key, "0040EEEE00010001");
  Assert.equal(details.msg, null);
});

test(function testGetValidKeysForMultipleRecipients() {
  KeyRingHelper.loadTestKeyList();

  const TRUSTLEVELS_SORTED = EnigmailTrust.trustLevelsSorted();
  let minTrustLevel = null;
  let details = null;
  let addrs = null;
  let keys = null;
  let keyMissing = null;

  // some matching keys:
  minTrustLevel = "?";
  addrs = ["full@enigmail-test.de",
    "multiple-onefull@enigmail-test.de",
    "multiple-twofull@enigmail-test.de",
    "multiple-onemarginal@enigmail-test.de",
    "withsubkey-uid1@enigmail-test.de",
    "withsubkey-uid2@enigmail-test.de"
  ];
  details = {};
  keys = [];
  keyMissing = EnigmailKeyRing.getValidKeysForAllRecipients(addrs, minTrustLevel, details, keys);
  Assert.equal(keyMissing, false);
  Assert.notEqual(keys, null);
  Assert.equal(keys.length, 6);
  Assert.equal(keys[0], "0x0003AAAA00010001");
  Assert.equal(keys[1], "0x0030AAAA00020001");
  Assert.equal(keys[2], "0x0034AAAA00020001");
  Assert.equal(keys[3], "0x0031AAAA00020001");
  Assert.equal(keys[4], "0x0040EEEE00010001");
  Assert.equal(keys[5], "0x0040EEEE00010001");
  Assert.equal(details.errArray.length, 0);

  // some non-matching keys:
  minTrustLevel = "?";
  addrs = ["no-encrypt@enigmail-test.de",
    "disabled@enigmail-test.de",
    "multiple-nofull@enigmail-test.de"
  ];
  details = {};
  keys = [];
  keyMissing = EnigmailKeyRing.getValidKeysForAllRecipients(addrs, minTrustLevel, details, keys);
  Assert.equal(keyMissing, true);
  Assert.equal(keys.length, 0);
  Assert.notEqual(details, null);
  Assert.equal(details.errArray.length, 3);
  Assert.equal(details.errArray[0].msg, "ProblemNoKey");
  Assert.equal(details.errArray[1].msg, "ProblemNoKey");
  Assert.equal(details.errArray[2].msg, "ProblemMultipleKeys");

  // just two keys:
  minTrustLevel = "?";
  addrs = ["0x0040EEEE00010001",
    "0x0003AAAA00010001",
    "0003AAAA00010001"
  ];
  details = {};
  keys = [];
  keyMissing = EnigmailKeyRing.getValidKeysForAllRecipients(addrs, minTrustLevel, details, keys);
  Assert.equal(keyMissing, false);
  Assert.notEqual(keys, null);
  Assert.equal(keys.length, 3);
  Assert.equal(keys[0], "0x0040EEEE00010001");
  Assert.equal(keys[1], "0x0003AAAA00010001");
  Assert.equal(keys[2], "0x0003AAAA00010001");
  Assert.equal(details.errArray.length, 0);

  // disabled key:
  // - this BEHAVIOR is PROBABLY WRONG:
  minTrustLevel = "?";
  addrs = ["0005AAAA00010001"];
  details = {};
  keys = [];
  keyMissing = EnigmailKeyRing.getValidKeysForAllRecipients(addrs, minTrustLevel, details, keys);
  Assert.equal(keyMissing, false);
  Assert.notEqual(keys, null);
  Assert.equal(keys.length, 1);
  Assert.equal(keys[0], "0x0005AAAA00010001");
  Assert.equal(details.errArray.length, 0);
});

test(function shouldGetKeyValidityErrors() {
  // from: gpg2 --with-fingerprint --fixed-list-mode --with-colons --list-keys
  let keyInfo = [
    // Key 1: Revoked key
    "tru::1:1443339321:1451577200:3:1:5",
    "pub:r:4096:1:DEF9FC808A3FF001:1388513885:1546188604::u:::sca:",
    "fpr:::::::::EA25EF48BF2001E41FAB0C1CDEF9FC808A3FF001:",
    "uid:r::::1389038412::44F73158EF0F47E4595B1FD8EC740519DE24B994::User ID 1 <user1@enigmail-test.net>:",
    "sub:r:4096:1:E2DEDFFB80C14584:1388513885:1546188603:::::e:",

    // Key 2: valid public key, usable for signing, with expired subkeys for encryption
    "pub:u:1024:17:F05B29A5CEFE4B70:1136219252:::u:::scaSCA:::::::",
    "fpr:::::::::6D67E7817D588BEA263F41B9F05B29A5CEFE4B70:",
    "uid:u::::1446568426::560DE55D9C611718F777EDD11A84F126CCD71965::User ID 2 <user2@enigmail-test.net>:::::::::",
    "sub:e:2048:1:B2417304FFC57041:1136219469:1199291469:::::e::::::",
    "sub:e:2048:1:770EA47A1DB0E8B0:1136221524:1293901524:::::s::::::",
    "sub:e:2048:1:805B29A5CEFB2B70:1199298291:1262370291:::::e::::::",
    "sub:e:2048:1:0F6B6901667E633C:1262537932:1325437132:::::e::::::",

    // Key 3: valid public key, usable subkey for encryption, no secret key
    "pub:u:1024:17:86345DFA372ADB32:1136219252:::u:::scESC:::::::",
    "fpr:::::::::9876E7817D588BEA263F41B986345DFA372ADB32:",
    "uid:u::::1446568426::560DE55D9C611718F777EDD11A84F126CCD71965::User ID 3 <user3@enigmail-test.net>:::::::::",
    "sub:u:2048:1:B2417304FFC57041:1136219469::::::s::::::",
    "sub:u:2048:1:770EA47A1DB0E8B0:1136221524::::::e::::::"
  ];

  // from: gpg2 --with-fingerprint --fixed-list-mode --with-colons --list-secret-keys
  let secKeyInfo = [
    // Key 1
    "sec::4096:1:DEF9FC808A3FF001:1388513885:1546188604:::::::::",
    "fpr:::::::::EA25EF48BF2001E41FAB0C1CDEF9FC808A3FF001:",
    "uid:::::::44F73158EF0F47E4595B1FD8EC740519DE24B994::User ID 1 <user1@enigmail-test.net>:",
    "ssb::4096:1:E2DEDFFB80C14584:1388513885::::::::::",
    // Key 2
    "sec:u:1024:17:F05B29A5CEFE4B70:1136219252:1507997328::u:::scaSCA:::::::",
    "fpr:::::::::6D67E7817D588BEA263F41B9F05B29A5CEFE4B70:",
    "uid:u::::1446568426::560DE55D9C611718F777EDD11A84F126CCD71965::User ID 2 <user2@enigmail-test.net>:::::::::",
    "ssb:e:2048:1:B2417304FFC57041:1136219469:1199291469:::::e::::::",
    "ssb:e:2048:1:770EA47A1DB0E8B0:1136221524:1293901524:::::s::::::",
    "ssb:e:2048:1:805B29A5CEFB2B70:1199298291:1262370291:::::e::::::",
    "ssb:e:2048:1:0F6B6901667E633C:1262537932:1325437132:::::e::::::"
    // NO Key 3
  ];

  createAndSortKeyList(keyInfo, secKeyInfo,
    "validity", // sorted acc. to key validity
    -1); // descending

  let key = EnigmailKeyRing.getKeyById("DEF9FC808A3FF001");
  let result = key.getSigningValidity();
  Assert.equal(result.reason, EnigmailLocale.getString("keyRing.pubKeyRevoked", [key.userId, "0x" + key.keyId]));

  key = EnigmailKeyRing.getKeyById("F05B29A5CEFE4B70");
  result = key.getEncryptionValidity();
  Assert.equal(result.keyValid, false);
  Assert.equal(result.reason, EnigmailLocale.getString("keyRing.encSubKeysExpired", [key.userId, "0x" + key.keyId]));

  result = key.getSigningValidity();
  Assert.equal(result.keyValid, true);

  key = EnigmailKeyRing.getKeyById("86345DFA372ADB32");
  result = key.getSigningValidity();
  Assert.equal(result.keyValid, false);
  Assert.equal(result.reason, EnigmailLocale.getString("keyRing.noSecretKey", [key.userId, "0x" + key.keyId]));

  result = key.getEncryptionValidity();
  Assert.equal(result.keyValid, true);
});

test(function shouldGetKeyExpiry() {
  // uses the key listing from shouldGetKeyValidityErrors
  let key = EnigmailKeyRing.getKeyById("DEF9FC808A3FF001");
  Assert.equal(key.getKeyExpiry(), 1546188603);

  key = EnigmailKeyRing.getKeyById("F05B29A5CEFE4B70");
  Assert.equal(key.getKeyExpiry(), 1325437132);

  key = EnigmailKeyRing.getKeyById("86345DFA372ADB32");
  Assert.equal(key.getKeyExpiry(), Number.MAX_VALUE);
});

test(function shouldClone() {
  // uses the key listing from shouldGetKeyValidityErrors
  let key = EnigmailKeyRing.getKeyById("DEF9FC808A3FF001");

  let cp = key.clone();

  Assert.equal(cp.fprFormatted, "EA25 EF48 BF20 01E4 1FAB 0C1C DEF9 FC80 8A3F F001");
  Assert.equal(cp.getEncryptionValidity().keyValid, false);
});


test(withLogFiles(withTestGpgHome(withEnigmail(function shouldImportFromFileAndGetKeyDetails() {
  const publicKey = do_get_file("resources/filterable-key.asc", false);
  const errorMsgObj = {};
  const importedKeysObj = {};
  const importResult = EnigmailKeyRing.importKeyFromFile(publicKey, errorMsgObj, importedKeysObj);
  Assert.assertContains(importedKeysObj.value, "CC68572FE740754B38D758D1227073A53A6FA857");
  Assert.equal(importResult, 0, errorMsgObj);
  const output = {
    "alice@example.org": "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",
    "alice@example.net": "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"
  };

  let keyOut = EnigmailKeyRing.getKeyById("CC68572FE740754B38D758D1227073A53A6FA857");
  for (var address in output) {
    let k = keyOut.getMinimalPubKey(address);
    Assert.equal(k.exitCode, 0);
    Assert.equal(k.errorMsg, "");
    EnigmailLog.DEBUG(" -> address: " + address +
      "\n -> wanted: " + output[address] +
      "\n ->    got: " + k.keyData +
      "\n");

    Assert.equal(k.keyData, output[address]);
  }
}))));
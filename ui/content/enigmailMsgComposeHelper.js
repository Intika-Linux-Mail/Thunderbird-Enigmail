/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "MPL"); you may not use this file
 * except in compliance with the MPL. You may obtain a copy of
 * the MPL at http://www.mozilla.org/MPL/
 *
 * Software distributed under the MPL is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the MPL for the specific language governing
 * rights and limitations under the MPL.
 *
 * The Original Code is Enigmail.
 *
 * The Initial Developer of the Original Code is Patrick Brunschwig.
 * Portions created by Patrick Brunschwig <patrick@enigmail.net> are
 * Copyright (C) 2004 Patrick Brunschwig. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 * ***** END LICENSE BLOCK ***** */


/**
 * helper functions for message composition
 */

Components.utils.import("resource://enigmail/enigmailCommon.jsm");
Components.utils.import("resource://enigmail/commonFuncs.jsm");

if (! Enigmail) var Enigmail = {};

Enigmail.hlp = {

  enigValidityKeyList: null,
  enigValidityKeySortList: null,

  /**
    *  check for the attribute of type "sign"/"encrypt"/"pgpMime" of the passed node
    *  and combine its value with oldVal and check for conflicts
    *    values might be: 0='never', 1='maybe', 2='always', 3='conflict'
    *  @oldVal:      original input value
    *  @node:        node of the rule in the DOM tree
    *  @type:        rule type name
    *  @return: result value after applying the rule (0/1/2)
    *           and combining it with oldVal
    */
  getFlagVal: function (oldVal, node, type)
  {
    var newVal = Number(node.getAttribute(type));
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js:    getFlagVal(): oldVal="+oldVal+" newVal="+newVal+" type=\""+type+"\"\n");

    // conflict remains conflict
    if (oldVal==EnigmailCommon.ENIG_CONFLICT) {
      return EnigmailCommon.ENIG_CONFLICT;
    }

    // 'never' and 'always' triggers conflict:
    if ((oldVal==EnigmailCommon.ENIG_NEVER && newVal==EnigmailCommon.ENIG_ALWAYS) || (oldVal==EnigmailCommon.ENIG_ALWAYS && newVal==EnigmailCommon.ENIG_NEVER)) {
      return EnigmailCommon.ENIG_CONFLICT;
    }

    // if there is any 'never' return 'never'
    // - thus: 'never' and 'maybe' => 'never'
    if (oldVal==EnigmailCommon.ENIG_NEVER || newVal==EnigmailCommon.ENIG_NEVER) {
      return EnigmailCommon.ENIG_NEVER;
    }

    // if there is any 'always' return 'always'
    // - thus: 'always' and 'maybe' => 'always'
    if (oldVal==EnigmailCommon.ENIG_ALWAYS || newVal==EnigmailCommon.ENIG_ALWAYS) {
      return EnigmailCommon.ENIG_ALWAYS;
    }

    // here, both values are 'maybe', which we return then
    return EnigmailCommon.ENIG_UNDEF;  // maybe
  },


  /**
    * process resulting sign/encryp/pgpMime mode for passed string of email addresses and
    * use rules and interactive rule dialog to replace emailAddrs by known keys
    * Input parameters:
    *  @emailAddrs:             comma and space separated string of addresses to process
    *  @interactive:            false: skip all interaction
    *  @forceRecipientSettings: force recipients settings for each missing key (if interactive==true)
    * Output parameters:
    *   @matchedKeysObj.value: string of matched keys and email addresses for which no key was found (or "")
    *   @flagsObj:       return value for combined sign/encrype/pgpMime mode
    *                    values might be: 0='never', 1='maybe', 2='always', 3='conflict'
    *
    * @return:  false if error occurred or processing was canceled
    */
  getRecipientsKeys: function (emailAddrs, interactive, forceRecipientSettings, matchedKeysObj, flagsObj)
  {
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getRecipientsKeys(): emailAddrs=\""+emailAddrs+"\" interactive="+interactive+" forceRecipientSettings="+forceRecipientSettings+"\n");

    const nsIEnigmail = Components.interfaces.nsIEnigmail;

    var enigmailSvc = EnigmailCommon.getService();
    if (!enigmailSvc) {
      return false;
    }

    // initialize return value and the helper variables for them:
    matchedKeysObj.value = "";
    flagsObj.value = false;
    var sign    = EnigmailCommon.ENIG_UNDEF;  // default sign flag is: maybe
    var encrypt = EnigmailCommon.ENIG_UNDEF;  // default encrypt flag is: maybe
    var pgpMime = EnigmailCommon.ENIG_UNDEF;  // default pgpMime flag is: maybe

    // list of addresses not processed
    // - string with { and } around each email to enable pattern matching with rules
    var openAddresses = "{"+EnigmailFuncs.stripEmail(emailAddrs.toLowerCase()).replace(/[, ]+/g, "}{")+"}";
    var foundAddresses = "";  // string of found addresses with { and } around
    var keyList = new Array;  // list of keys found for all Addresses
    var addrKeysList = new Array;

    // process recipient rules
    var rulesListObj= new Object;
    if (enigmailSvc.getRulesData(rulesListObj)) {

      var rulesList=rulesListObj.value;

      if (rulesList.firstChild.nodeName=="parsererror") {
        EnigmailCommon.alert(window, "Invalid pgprules.xml file:\n"+ rulesList.firstChild.textContent);
        return false;
      }
      EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getRecipientsKeys(): rules successfully loaded; now process them\n");

      // go through all rules to find match with email addresses
      // - note: only if key field has a value, addresses are done with processing
      for (let node=rulesList.firstChild.firstChild; node; node = node.nextSibling) {
        if (node.tagName=="pgpRule") {
          try {
            var nodeText=node.getAttribute("email");
            if (!nodeText) {
              continue;
            }
            var negateRule = false;
            if (node.getAttribute("negateRule")) {
              negateRule = Number(node.getAttribute("negateRule"));
            }
            if (! negateRule) {
              // normal rule
              addrList=nodeText.toLowerCase().split(/[ ,;]+/);
              for (var addrIndex=0; addrIndex < addrList.length; addrIndex++) {
                var email = addrList[addrIndex];  // email has format such as '{name@qqq.de}' or '@qqq' or '{name' or '@qqq.de}'
                let idx = openAddresses.indexOf(email);
                if (idx >= 0) {
                  EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getRecipientsKeys(): got matching rule for \""+email+"\"\n");

                  // process sign/encrypt/ppgMime settings
                  sign    = this.getFlagVal(sign,    node, "sign");
                  encrypt = this.getFlagVal(encrypt, node, "encrypt");
                  pgpMime = this.getFlagVal(pgpMime, node, "pgpMime");

                  // process keys
                  let keyIds = node.getAttribute("keyId");
                  if (keyIds) {
                    // either we have a key or "." for "do not check further rules for this address"
                    // => process rule for each matching email address
                    while (idx >= 0) {
                      // - extract matching address and its indexes (where { starts and after } ends)
                      let start = openAddresses.substring(0, idx+email.length).lastIndexOf("{");
                      let end   = start + openAddresses.substring(start).indexOf("}")+1;
                      let foundAddr = openAddresses.substring(start+1,end-1);  // without { and }
                      // - assign key if one exists (not ".")
                      if (keyIds != ".") {  // if NOT "do not check further rules for this address"
                        let ids = keyIds.replace(/[ ,;]+/g, ", ");
                        keyList.push(ids);
                        let elem = {addr:foundAddr,keys:ids};
                        addrKeysList.push(elem);
                      }
                      // - remove found address from openAdresses and add it to foundAddresses (with { and } as delimiters)
                      openAddresses = openAddresses.substring(0,start) + openAddresses.substring(end);
                      foundAddresses += "{"+foundAddr+"}";
                      // - check whether we have any other matching address for the same rule
                      idx = openAddresses.indexOf(email,start);
                    }
                  }
                }
              }
            }
            else {
              // "not" rule
              addrList = openAddresses.replace(/\}\{/g, "},{").split(/,/);
              var idx;
              for (idx = 0; idx < addrList.length; idx++) {
                if (nodeText.toLowerCase().indexOf(addrList[idx])>=0) {
                  idx = addrList.length+2;
                  break;
                }
              }
              if (idx == addrList.length) {
                // no matching address; apply rule
                sign    = this.getFlagVal(sign,    node, "sign");
                encrypt = this.getFlagVal(encrypt, node, "encrypt");
                pgpMime = this.getFlagVal(pgpMime, node, "pgpMime");
                keyIds=node.getAttribute("keyId");
                if (keyIds) {
                  if (keyIds != ".") {
                    let ids = keyIds.replace(/[ ,;]+/g, ", ");
                    keyList.push(ids);
                    let foundAddr = "{}";
                    let elem = {addr:foundAddr,keys:ids};
                    addrKeysList.push(elem);
                  }
                }
              }
            }
          }
          catch (ex) {}
        }
      }
    }

    // if interactive and requested: start individual recipient settings dialog for each missing key
    if (interactive && forceRecipientSettings) {
      var addrList=emailAddrs.split(/,/);
      var inputObj=new Object;
      var resultObj=new Object;
      for (i=0; i<addrList.length; i++) {
        if (addrList[i].length>0) {
          var theAddr=EnigmailFuncs.stripEmail(addrList[i]).toLowerCase();
          if ((foundAddresses.indexOf("{"+theAddr+"}")==-1) &&
              (! (theAddr.indexOf("0x")==0 && theAddr.indexOf("@")==-1))) {
            inputObj.toAddress="{"+theAddr+"}";
            inputObj.options="";
            inputObj.command = "add";
            window.openDialog("chrome://enigmail/content/enigmailSingleRcptSettings.xul","", "dialog,modal,centerscreen,resizable", inputObj, resultObj);
            if (resultObj.cancelled==true) {
              return false;
            }

            // create a getAttribute() function for getFlagVal to work normally
            resultObj.getAttribute = function(attrName) {
              return this[attrName];
            };
            if (!resultObj.negate) {
              sign    = this.getFlagVal(sign,    resultObj, "sign");
              encrypt = this.getFlagVal(encrypt, resultObj, "encrypt");
              pgpMime = this.getFlagVal(pgpMime, resultObj, "pgpMime");
              if (resultObj.keyId.length>0) {
                keyList.push(resultObj.keyId);
                let elem = {addr:theAddr,keys:resultObj.keyId};
                addrKeysList.push(elem);
                let replaceAddr = new RegExp("{"+addrList[i]+"}", "g");
                openAddresses = openAddresses.replace(replaceAddr, "");
              }
              else {
                // no key -> no encryption
                encrypt=0;
              }
            }
          }
        }
      }
    }

    // OLD: if we found key, return keys AND unprocessed addresses in matchedKeysObj.value
    if (keyList.length>0) {
      // sort key list and make it unique?
      matchedKeysObj.value = keyList.join(", ");
      matchedKeysObj.value += openAddresses.replace(/\{/g, ", ").replace(/\}/g, "");
    }
    // NEW:
    matchedKeysObj.addrKeysList = addrKeysList;
    matchedKeysObj.openAddrStr = openAddresses.replace(/\{/, "").replace(/\{/g, ", ").replace(/\}/g, "");

    // return result from combining flags
    flagsObj.sign = sign;
    flagsObj.encrypt = encrypt;
    flagsObj.pgpMime = pgpMime;
    flagsObj.value = true;

    EnigmailCommon.DEBUG_LOG("   found keys:\n");
    for (let i = 0; i < matchedKeysObj.addrKeysList.length; i++) {
      EnigmailCommon.DEBUG_LOG("     " + matchedKeysObj.addrKeysList[i].addr + ": " + matchedKeysObj.addrKeysList[i].keys + "\n");
    }
    EnigmailCommon.DEBUG_LOG("   open addresses:\n");
    EnigmailCommon.DEBUG_LOG("     " + matchedKeysObj.openAddrStr + "\n");

    return true;
  },


  /* try to find valid key to passed email address
   * @return: list of all found key (with leading "0x") or null
   *          details in details parameter
   */
  validKeysForAllRecipients: function (emailsOrKeys, details)
  {
    EnigmailCommon.DEBUG_LOG("=====> validKeysForAllRecipients()\n");
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: validKeysForAllRecipients(): emailsOrKeys='"+emailsOrKeys+"'\n");

    // check whether to use our internal cache
    var resultingArray = null;
    resultingArray = this.doValidKeysForAllRecipients(emailsOrKeys,details);

    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: validKeysForAllRecipients(): return '"+resultingArray+"'\n");
    EnigmailCommon.DEBUG_LOG("  <=== validKeysForAllRecipients()\n");
    return resultingArray;
  },

  doValidKeysForAllRecipients: function (emailsOrKeys, details)
  {
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: doValidKeysForAllRecipients(): emailsOrKeys='"+emailsOrKeys+"'\n");

    // check which keys are accepted
    var minTrustLevel;
    var acceptedKeys = EnigmailCommon.getPref("acceptedKeys");
    switch (acceptedKeys) {
      case 0: // accept valid/authenticated keys only
        minTrustLevel = "f";  // first value for trusted keys
        break;
      case 1: // accept all but revoked/disabled/expired keys
        minTrustLevel = "?";  // value between invalid and unknown keys
        break;
      default:
        EnigmailCommon.DEBUG_LOG("enigmailMsgComposeOverlay.js: doValidKeysForAllRecipients(): return null (INVALID VALUE for acceptedKeys: \""+acceptedKeys+"\")\n");
        return null;
        break;
    }

    const TRUSTLEVELS_SORTED = EnigmailFuncs.trustlevelsSorted();
    var minTrustLevelIndex = TRUSTLEVELS_SORTED.indexOf(minTrustLevel);
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: doValidKeysForAllRecipients(): find keys with minTrustLevel=\""+minTrustLevel+"\"\n");

    var resultingArray = new Array;  // resulting key list (if all valid)
    try {
      // get list of known keys
      if (!keyList) {
        var keyListObj = {};
        EnigmailFuncs.loadKeyList(window,
                                  false,      // refresh key infos if required
                                  keyListObj,   // returned list
                                  "validity",   // sorted acc. to key validity
                                  -1);          // descending
        this.enigValidityKeyList = keyListObj.keyList;
        this.enigValidityKeySortList = keyListObj.keySortList;
      }
      var keyList = this.enigValidityKeyList;
      var keySortList = this.enigValidityKeySortList;

      // ****** DEBUG ************** print keyList (debug issue)
      //EnigmailCommon.DEBUG_LOG("                   keyList:\n");
      //EnigmailCommon.DEBUG_LOG("                   length:  "+ keySortList.length + "\n");
      //for (var idx=0; idx<keySortList.length; idx++) { // note: we have sorted acc. to validity
      //  var keyObj = keyList[keySortList[idx].keyId];
      //  EnigmailCommon.DEBUG_LOG("                   [" + idx + "].keyId:  "+ keyObj.keyId + "\n");
      //  EnigmailCommon.DEBUG_LOG("                   [" + idx + "].userId: "+ keyObj.userId + "\n");
      //}

      // create array of address elements (email or key)
      var addresses=EnigmailFuncs.stripEmail(emailsOrKeys).split(',');

      var gpgGroups = EnigmailCommon.getGpgGroups();

      // resolve GnuPG groups
      for (i=0; i < addresses.length; i++) {
        var addr = addresses[i].toLowerCase();
        for (var j = 0; j < gpgGroups.length; j++) {
          if (addr == gpgGroups[j].alias.toLowerCase() ||
              "<" + addr + ">" == gpgGroups[j].alias.toLowerCase()) {
            // replace address with keylist
            var grpList = gpgGroups[j].keylist.split(/;/);
            addresses[i] = grpList[0];
            for (var k = 1; k < grpList.length; k++) {
              addresses.push(grpList[k]);
            }
          }
        }
      }

      // check whether each address is or has a key:
      var keyMissing = false;
      if (details) {
        details.errArray = new Array;
      }
      for (i=0; i < addresses.length; i++) {
        var addr = addresses[i];
        // try to find current address in key list:
        var found = false;
        var errMsg = null;
        if (addr.indexOf('@') >= 0) {
          // try email match:
          var addrErrDetails = new Object;
          var key = this.getValidKeyForRecipient (addr, minTrustLevelIndex, keyList, keySortList, addrErrDetails);
          if (details && addrErrDetails.msg) {
            errMsg = addrErrDetails.msg;
          }
          if (key) {
            found = true;
            resultingArray.push("0x"+key.toUpperCase());
          }
        }
        else {
          // try key match:
          var key = addr;
          if (addr.search(/^0x/i) == 0) {
            key = addr.substring(2);  // key list has elements without leading "0x"
          }
          var keyObj = keyList[key.toUpperCase()];  // note: keylist has keys with uppercase only

          if (! keyObj && addr.search(/^0x[A-F0-9]{8}([A-F0-9]{8})*$/i) == 0) {
            // we got a key ID, probably from gpg.conf?

            key = key.substr(-16, 16);

            for (let j in keyList) {
              if (j.endsWith(key)) {
                keyObj = keyList[j];
                break;
              }
            }
          }
          if (keyObj) {
            var keyTrust = keyObj.keyTrust;
            // if found, check whether the trust level is enough
            if (TRUSTLEVELS_SORTED.indexOf(keyTrust) >= minTrustLevelIndex) {
              found = true;
              resultingArray.push(addr);
            }
          }
        }
        if (! found) {
          // no key for this address found
          keyMissing = true;
          if (details) {
            if (!errMsg) {
              errMsg = "ProblemNoKey";
            }
            var detailsElem = new Object;
            detailsElem.addr = addr;
            detailsElem.msg = errMsg;
            details.errArray.push(detailsElem);
          }
          EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: doValidKeysForAllRecipients(): return null (no single valid key found for=\""+addr+"\" with minTrustLevel=\""+minTrustLevel+"\")\n");
        }
      }
    }
    catch (ex) {
      EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: doValidKeysForAllRecipients(): return null (exception: "+ex.description+")\n");
      return null;
    }
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: doValidKeysForAllRecipients(): return \""+resultingArray+"\"\n");
    if (keyMissing) {
      return null;
    }
    return resultingArray;
  },


  /* try to find valid key for encryption to passed email address
   * @param details if not null returns error in details.msg
   * @return: found key (without leading "0x") or null
   */
  getValidKeyForRecipient: function (emailAddr, minTrustLevelIndex, keyList, keySortList, details)
  {
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient(): emailAddr=\""+emailAddr+"\"\n");
    const TRUSTLEVELS_SORTED = EnigmailFuncs.trustlevelsSorted();
    const fullTrustIndex = TRUSTLEVELS_SORTED.indexOf("f");

    emailAddr = emailAddr.toLowerCase();
    var embeddedEmailAddr = "<" + emailAddr +">";

    // note: we can't take just the first matched because we might have faked keys as duplicates
    var foundKeyId = null;
    var foundTrustLevel = null;

    // **** LOOP to check against each key
    // - note: we have sorted the keys according to validity
    //         to abort the loop as soon as we reach keys that are not valid enough
    for (var idx=0; idx<keySortList.length; idx++) {
      var keyObj = keyList[keySortList[idx].keyId];
      var keyTrust = keyObj.keyTrust;
      var keyTrustIndex = TRUSTLEVELS_SORTED.indexOf(keyTrust);
      //EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  check key " + keyObj.keyId + "\n");

      // key trust (our sort criterion) too low?
      // => *** regular END of the loop
      if (keyTrustIndex < minTrustLevelIndex) {
        if (foundKeyId == null) {
          if (details) {
            details.msg = "ProblemNoKey";
          }
          var msg = "no key with enough trust level for '" + emailAddr + "' found";
          EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  " + msg + "\n");
        }
        return foundKeyId;  // **** regular END OF LOOP (return NULL or found single key)
      }

      // key valid for encryption?
      if (keyObj.keyUseFor.indexOf("E") < 0) {
        //EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  skip key " + keyObj.keyId + " (not provided for encryption)\n");
        continue;  // not valid for encryption => **** CONTINUE the LOOP
      }
      // key disabled?
      if (keyObj.keyUseFor.indexOf("D") >= 0) {
        //EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  skip key " + keyObj.keyId + " (disabled)\n");
        continue;  // disabled => **** CONTINUE the LOOP
      }

      // check against the user ID
      var userId = keyObj.userId.toLowerCase();
      if (userId && (userId == emailAddr || userId.indexOf(embeddedEmailAddr) >= 0)) {
        if (keyTrustIndex < minTrustLevelIndex) {
          EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  matching key="+keyObj.keyId+" found but not enough trust\n");
        }
        else {
          // key with enough trust level found
          EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  key="+keyObj.keyId+" keyTrust=\""+keyTrust+"\" found\n");

          // immediately return if a fully or ultimately trusted key is found
          // (faked keys should not be an issue here, so we don't have to check other keys)
          if (keyTrustIndex >= fullTrustIndex) {
            return keyObj.keyId;
          }

          if (foundKeyId != keyObj.keyId) {
            // new matching key found (note: might find same key via subkeys)
            if (foundKeyId != null) {
              // different matching keys found
              if (foundKeyTrustIndex > keyTrustIndex) {
                return foundKeyId;   // OK, previously found key has higher trust level
              }
              // error because we have two keys with same trust level
              // => let the user decide (to prevent from using faked keys with default trust level)
              if (details) {
                details.msg = "ProblemMultipleKeys";
              }
              var msg = "multiple matching keys with same trust level found for '" + emailAddr + "' ";
              EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  " + msg
                                       + " trustLevel=\"" + keyTrust + "\" (0x" + foundKeyId + " and 0x" + keyObj.keyId + ")\n");
              return null;
            }
            // save found key to compare with other matching keys (handling of faked keys)
            foundKeyId = keyObj.keyId;
            foundKeyTrustIndex = keyTrustIndex;
          }
          continue;  // matching key found (again) => **** CONTINUE the LOOP (don't check Sub-UserIDs)
        }
      }

      // check against the sub user ID
      // (if we are here, the primary user ID didn't match)
      // - Note: sub user IDs have NO owner trust
      for (var subUidIdx=0; subUidIdx<keyObj.SubUserIds.length; subUidIdx++) {
        var subUidObj = keyObj.SubUserIds[subUidIdx];
        var subUserId = subUidObj.userId.toLowerCase();
        var subUidTrust = subUidObj.keyTrust;
        var subUidTrustIndex = TRUSTLEVELS_SORTED.indexOf(subUidTrust);
        //EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  check subUid " + subUidObj.keyId + "\n");

        if (subUserId && (subUserId == emailAddr || subUserId.indexOf(embeddedEmailAddr) >= 0)) {
          if (subUidTrustIndex < minTrustLevelIndex) {
            EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  matching subUid="+keyObj.keyId+" found but not enough trust\n");
          }
          else {
            // subkey with enough trust level found
            EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  matching subUid in key="+keyObj.keyId+" keyTrust=\""+keyTrust+"\" found\n");

            if (keyTrustIndex >= fullTrustIndex) {
              // immediately return if a fully or ultimately trusted key is found
              // (faked keys should not be an issue here, so we don't have to check other keys)
              return keyObj.keyId;
            }

            if (foundKeyId != keyObj.keyId) {
              // new matching key found (note: might find same key via different subkeys)
              if (foundKeyId != null) {
                // different matching keys found
                if (foundKeyTrustIndex > subUidTrustIndex) {
                  return foundKeyId;   // OK, previously found key has higher trust level
                }
                // error because we have two keys with same trust level
                // => let the user decide (to prevent from using faked keys with default trust level)
                if (details) {
                  details.msg = "ProblemMultipleKeys";
                }
                var msg = "multiple matching keys with same trust level found for '" + emailAddr + "' ";
                EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  " + msg
                                         + " trustLevel=\"" + keyTrust + "\" (0x" + foundKeyId + " and 0x" + keyObj.keyId + ")\n");
                return null;
              }
              // save found key to compare with other matching keys (handling of faked keys)
              foundKeyId = keyObj.keyId;
              foundKeyTrustIndex = subUidTrustIndex;
            }
          }
        }
      }

    } // **** LOOP to check against each key

    if (foundKeyId == null) {
      EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getValidKeyForRecipient():  no key for '" + emailAddr + "' found\n");
    }
    return foundKeyId;
  },


  /**
    * processConflicts
    * - handle sign/encrypt/pgpMime conflicts if any
    * - NOTE: conflicts result into disabling the feature (0/never)
    * Input parameters:
    *  @encrypt: email would currently get encrypted
    *  @sign:    email would currently get signed
    * @return:  false if error occurred or processing was canceled
    */
  processConflicts: function (encrypt, sign)
  {
    // process message about whether we still sign/encrypt
    var msg = "";
    msg += "\n"+"- " + EnigmailCommon.getString(encrypt ? "encryptYes" : "encryptNo");
    msg += "\n"+"- " + EnigmailCommon.getString(sign ? "signYes" : "signNo");
    if (EnigmailCommon.getPref("warnOnRulesConflict")==2) {
      EnigmailCommon.setPref("warnOnRulesConflict", 0);
    }
    if (!EnigmailCommon.confirmPref(window, EnigmailCommon.getString("rulesConflict", [ msg ]), "warnOnRulesConflict")) {
      return false;
    }
    return true;
  },


  /**
   * determine invalid recipients as returned from GnuPG
   *
   * @gpgMsg: output from GnuPG
   *
   * @return: space separated list of invalid addresses
   */
  getInvalidAddress: function (gpgMsg)
  {
    EnigmailCommon.DEBUG_LOG("enigmailMsgComposeHelper.js: getInvalidAddress(): gpgMsg=\""+gpgMsg+"\"\n\n");
    var invalidAddr = [];
    var lines = gpgMsg.split(/[\n\r]+/);
    for (var i=0; i < lines.length; i++) {
      var m = lines[i].match(/^(INV_RECP \d+ )(.*)$/);
      if (m && m.length == 3) {
        invalidAddr.push(EnigmailFuncs.stripEmail(m[2].toLowerCase()));
      }
    }
    return invalidAddr.join(" ");
  }

};

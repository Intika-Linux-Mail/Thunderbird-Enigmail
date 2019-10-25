/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* global dump: false */

"use strict";

var EXPORTED_SYMBOLS = ["JSUnit"];

const Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const Assert = ChromeUtils.import("chrome://enigmail/content/jsunit/Assert.jsm").Assert;

var gTestError = 0;
var gTestSucceed = 0;
var gTestPending = 0;
var gLogFileStream = "";

var gCurrDir = "";

function DEBUG_LOG(str) {
  dump("jsunit-main.jsm: " + str + "\n");
}

function generateQI(aCid) {
  if ("generateQI" in ChromeUtils) {
    return ChromeUtils.generateQI(aCid);
  }
  else {
    let XPCOMUtils = Cu.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;
    return XPCOMUtils.generateQI(aCid);
  }
}


var JSUnit = {

  assert: null,

  // printMsg: log stuff

  dumpMsg: function(str) {
    dump(str + "\n");
  },

  logToFile: function(str) {
    gLogFileStream.write(str + "\n", str.length + 1);
  },

  testSucceeded: function() {
    gTestSucceed++;
  },

  testFailed: function() {
    gTestError++;
  },

  setLogFile: function(logFileName) {
    gLogFileStream = this.createFileStream(logFileName);
  },

  logTestResult: function(err, message, stack) {
    if (err) {
      JSUnit.testFailed();
      JSUnit.printMsg(err + " - " + stack);
    }
    else {
      JSUnit.testSucceeded();
      JSUnit.printMsg("Succeed: " + message + " - " + stack);
    }
  },

  printStats: function() {
    JSUnit.printMsg("\nJSUNIT FINAL STATS\n");
    JSUnit.printMsg("TestResult: executed : " + (JSUnit.countFailed() + JSUnit.countSucceeded()));
    JSUnit.printMsg("TestResult: succeeded: " + JSUnit.countSucceeded());
    JSUnit.printMsg("TestResult: failed   : " + JSUnit.countFailed());

    if (gLogFileStream) {
      gLogFileStream.close();
    }
    gTestSucceed = 0;
    gTestError = 0;
  },


  init: function(useTinyJsd, logFileName) {
    // initialize library
    gCurrDir = Components.classes["@mozilla.org/file/directory_service;1"]
      .getService(Components.interfaces.nsIDirectoryServiceProvider)
      .getFile("CurWorkD", {});
    this.assert = new Assert(this.logTestResult);

    if (logFileName) {
      this.setLogFile(logFileName);
      this.printMsg = this.logToFile;
    }
    else {
      // fallback: command line interface
      this.printMsg = this.dumpMsg;
    }
  },

  setMainFile: function(fileName) {
  },

  getOS: function() {
    return Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime).OS;
  },

  getCwd: function() {
    return gCurrDir.clone();
  },

  getFile: function(stack, testdirRelativePath, allowNonexistent) {

    //DEBUG_LOG("getFile: "+gCurrDir);

    var fn = gCurrDir.path + "/" + testdirRelativePath;

    if (this.getOS() == "WINNT") {
      fn = fn.replace(/\//g, "\\");
    }

    var lf = Components.classes["@mozilla.org/file/local;1"].createInstance(
      Components.interfaces.nsIFile);
    lf.initWithPath(fn);

    if (!(allowNonexistent || lf.exists())) {
      JSUnit.logTestResult("AssertionError: file '" + fn + "' not found", null,
        stack.filename +
        " :: " + stack.name +
        " :: line " + stack.lineNumber);
      return null;
    }
    else {
      JSUnit.logTestResult(null, "file '" + fn + "' OK",
        stack.filename +
        " :: " + stack.name +
        " :: line " + stack.lineNumber);
    }
    return lf;
  },


  makeUrl: function(scriptFile, isAbsolutePath) {
    var isUrl = false;
    if (scriptFile.search(/^(chrome|file|resource):\/\//) == 0) {
      isAbsolutePath = true;
      isUrl = true;
    }

    if (!isAbsolutePath) {
      scriptFile = "file://" + gCurrDir.path + "/" + scriptFile;
    }
    if (!isUrl) {
      scriptFile = "file://" + scriptFile;
    }

    scriptFile = scriptFile.replace(/^(file:\/\/)+/, "file://");
    return scriptFile;
  },

  createFileStream: function(filePath) {

    const NS_RDONLY = 0x01;
    const NS_WRONLY = 0x02;
    const NS_CREATE_FILE = 0x08;
    const NS_TRUNCATE = 0x20;
    const DEFAULT_FILE_PERMS = 0x180; // equals 0600

    let localFile;
    filePath = gCurrDir.path + "/" + filePath;
    if (this.getOS() == "WINNT") {
      filePath = filePath.replace(/\//g, "\\");
    }

    dump("Creating log file: " + filePath + "\n");

    localFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    localFile.initWithPath(filePath);

    if (!localFile.exists()) {
      localFile.persistentDescriptor = filePath;
    }

    if (localFile.exists()) {

      if (localFile.isDirectory() || !localFile.isWritable())
        throw Components.results.NS_ERROR_FAILURE;
    }

    const flags = NS_WRONLY | NS_CREATE_FILE | NS_TRUNCATE;
    const fileStream = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(Ci.nsIFileOutputStream);

    fileStream.init(localFile, flags, DEFAULT_FILE_PERMS, 0);

    return fileStream;
  },

  executeScript: function(scriptFile, isAbsolutePath, dontRun) {
    scriptFile = JSUnit.makeUrl(scriptFile, isAbsolutePath);

    let context = {};
    Services.scriptloader.loadSubScript("chrome://enigmail/content/jsunit/jsunit-wrapper.js", context, "UTF-8");
    Services.scriptloader.loadSubScript(scriptFile, context, "UTF-8");
    if (!dontRun) {
      Services.scriptloader.loadSubScript("chrome://enigmail/content/jsunit/jsunit-exec.js", context, "UTF-8");
    }

    if (gTestPending) {
      JSUnit.waitForAsyncTest();
    }
  },

  loadScript: function(urlString, context) {
    try {
      Services.scriptloader.loadSubScript(urlString, context, "UTF-8");
    }
    catch (ex) {
      JSUnit.printMsg("Failed to load '" + urlString + "' into " + context + "\n");
      JSUnit.printMsg(ex.toString() + "\n");
      JSUnit.printMsg(ex.stack + "\n");
      throw "ERROR while loading script";
    }
  },

  abortPendingTests: function() {
    gTestPending = 0;
  },

  testPending: function() {
    ++gTestPending;
  },

  waitForAsyncTest: function() {
    var thread = Cc['@mozilla.org/thread-manager;1'].getService(Ci.nsIThreadManager).currentThread;
    while (gTestPending > 0) {
      thread.processNextEvent(true);
    }
  },

  testFinished: function() {
    if (gTestPending > 0) --gTestPending;
  },

  countSucceeded: function() {
    return gTestSucceed;
  },

  countFailed: function() {
    return gTestError;
  },

  // create empty DOM document
  createDOMDocument: function() {

    let appShellSvc = Cc["@mozilla.org/appshell/appShellService;1"].getService(Ci.nsIAppShellService);

    let doc = appShellSvc.hiddenDOMWindow.document;

    return doc;
  },

  // create a non-function nsIDOMWindow object that can be used as stub
  createStubWindow: function() {
    var w = {
      QueryInterface: generateQI(["nsIDOMWindow"]),
      window: null,
      self: null,
      document: null,
      name: "JSUtil Stub Window",
      location: null,
      history: null,
      locationbar: null,
      menubar: null,
      personalbar: null,
      scrollbars: null,
      statusbar: null,
      toolbar: null,
      status: "",
      close: function() {},
      stop: function() {},
      focus: function() {},
      blur: function() {},
      length: 0,
      top: null,
      parent: null,
      opener: null,
      frameElement: null,
      navigator: {
        QueryInterface: generateQI(["nsIDOMNavigator"]),
        appCodeName: "JSUnit",
        appName: "JSUnit",
        appVersion: "1",
        language: "en",
        platform: "",
        oscpu: "",
        vendor: "",
        vendorSub: "",
        product: "",
        productSub: "",
        userAgent: "",
        buildID: "",
        doNotTrack: ""
      },

      applicationCache: null,
      alert: function() {},
      confirm: function() {},
      prompt: function() {},
      print: function() {},
      showModalDialog: function() {},
      postMessage: function() {},
      atob: function(s) {
        return atob(s);
      },
      btoa: function(s) {
        return btoa(s);
      },
      sessionStorage: null,
      localStorage: null,
      indexedDB: null,
      mozIndexedDB: null,
      getSelection: function() {},
      matchMedia: function() {},
      screen: null,
      innerWidth: 0,
      innerHeight: 0,
      scrollX: 0,
      pageXOffset: 0,
      scrollY: 0,
      pageYOffset: 0,
      scroll: function() {},
      scrollTo: function() {},
      scrollBy: function() {},
      screenX: 0,
      screenY: 0,
      outerWidth: 0,
      outerHeight: 0,
      getComputedStyle: function() {},
      getDefaultComputedStyle: function() {},
      scrollByLines: function() {},
      scrollByPages: function() {},
      sizeToContent: function() {},
      closed: false,
      crypto: null,
      mozInnerScreenX: 0.0,
      mozInnerScreenY: 0.0,
      devicePixelRatio: 1.0,
      scrollMaxX: 0,
      scrollMaxY: 0,
      fullScreen: false,
      back: function() {},
      forward: function() {},
      home: function() {},
      moveTo: function() {},
      moveBy: function() {},
      resizeTo: function() {},
      resizeBy: function() {},
      open: function() {},
      openDialog: function() {},
      updateCommands: function() {},
      find: function() {},
      mozPaintCount: 0,
      mozRequestAnimationFrame: function() {},
      requestAnimationFrame: function() {},
      mozCancelAnimationFrame: function() {},
      mozCancelRequestAnimationFrame: function() {},
      cancelAnimationFrame: function() {},
      mozAnimationStartTime: 0,
      onafterprint: null,
      onbeforeprint: null,
      onbeforeunload: null,
      onhashchange: null,
      onlanguagechange: null,
      onmessage: null,
      onoffline: null,
      ononline: null,
      onpopstate: null,
      onpagehide: null,
      onpageshow: null,
      // Not supported yet (Gecko 32)
      onredo: null,
      onresize: null,
      // Not supported yet (Gecko 32)
      onstorage: null,
      // Not supported yet (Gecko 32)
      onundo: null,
      onunload: null,
      ondevicemotion: null,
      ondeviceorientation: null,
      ondeviceproximity: null,
      onuserproximity: null,
      ondevicelight: null,
      onmouseenter: null,
      onmouseleave: null,
      console: null,
      addEventListener: function() {}
    };

    w.self = w;
    w.top = w;
    w.parent = w;
    return w;
  }
};

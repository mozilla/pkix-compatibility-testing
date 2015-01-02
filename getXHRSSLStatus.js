/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

/* === This is the stuff you might want to change === */
if (!arguments || arguments.length < 1) {
  throw "Usage: xpcshell getXHRSSLStatus.js <domains-file> [error-output] [ev-output]\n";
}
const SOURCE = arguments[0];     // this can be an http URI if you want
const ERROR_OUTPUT = arguments[1] || ("error-" + SOURCE);
const EV_OUTPUT = arguments[2] || ("ev-" + SOURCE);
const MAX_CONCURRENT_REQUESTS = 16;
const MAX_RETRIES = 0;
const REQUEST_TIMEOUT = 10 * 1000;

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;
const Cr = Components.results;

// Register resource://app/ URI
let ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
let resHandler = ios.getProtocolHandler("resource")
  .QueryInterface(Ci.nsIResProtocolHandler);
let mozDir = Cc["@mozilla.org/file/directory_service;1"]
  .getService(Ci.nsIProperties)
  .get("CurProcD", Ci.nsILocalFile);
let mozDirURI = ios.newFileURI(mozDir);
resHandler.setSubstitution("app", mozDirURI);

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
XPCOMUtils.defineLazyGetter(this, "Timer", function() {
  let timer = {};
  Cu.import("resource://gre/modules/Timer.jsm", timer);
  return timer;
});

const nsINSSErrorsService = Ci.nsINSSErrorsService;
let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
const UNKNOWN_ERROR = 0x8000ffff;

function readHttp() {
  let req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
    .createInstance(Ci.nsIXMLHttpRequest);
  req.open("GET", SOURCE, false); // doing the request synchronously
  try {
    req.send();
  } catch (e) {
    dump("ERROR: problem downloading '" + SOURCE + "': " + e);
    return [];
  }

  if (req.status !== 200) {
    dump("ERROR: problem downloading '" + SOURCE + "': status " + req.status);
    return [];
  }

  return req.responseText;
}

function readFile() {
  let file = Cc["@mozilla.org/file/directory_service;1"]
    .getService(Components.interfaces.nsIProperties)
    .get("CurWorkD", Components.interfaces.nsILocalFile);
  file.append(SOURCE);
  let stream = Cc["@mozilla.org/network/file-input-stream;1"]
                 .createInstance(Ci.nsIFileInputStream);
  stream.init(file, -1, 0, 0);
  return NetUtil.readInputStreamToString(stream, stream.available());
}

// downloads a file containing host names
function downloadHosts() {
  let str;
  let scheme = SOURCE.split(":", 1)[0].toLowerCase();
  if (scheme === "http" || scheme == "https") {
    str = readHttp();
  } else {
    str = readFile();
  }
  return str.split("\n").map(e => e.trim()).filter(e => !!e);
}

function createTCPError(status) {
  let errType, errName;
  if ((status & 0xff0000) === 0x5a0000) { // Security module
    let errorClass;
    // getErrorClass will throw a generic NS_ERROR_FAILURE if the error code is
    // somehow not in the set of covered errors.
    try {
      errorClass = nssErrorsService.getErrorClass(status);
    } catch (ex) {
      errorClass = 'SecurityProtocol';
    }
    if (errorClass == nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
      errType = 'SecurityCertificate';
    } else {
      errType = 'SecurityProtocol';
    }

    // NSS_SEC errors (happen below the base value because of negative vals)
    if ((status & 0xffff) < Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
      // The bases are actually negative, so in our positive numeric space, we
      // need to subtract the base off our value.
      let nssErr = Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE) - (status & 0xffff);
      switch (nssErr) {
      case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
        errName = 'SecurityExpiredCertificateError';
        break;
      case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
        errName = 'SecurityRevokedCertificateError';
        break;

        // per bsmith, we will be unable to tell these errors apart very soon,
        // so it makes sense to just folder them all together already.
      case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
      case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
      case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
      case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
        errName = 'SecurityUntrustedCertificateIssuerError';
        break;
      case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
        errName = 'SecurityInadequateKeyUsageError';
        break;
      case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
        errName = 'SecurityCertificateSignatureAlgorithmDisabledError';
        break;
      default:
        errName = 'SecurityError';
        break;
      }
    } else {
      let sslErr = Math.abs(nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (status & 0xffff);
      switch (sslErr) {
      case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
        errName = 'SecurityNoCertificateError';
        break;
      case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
        errName = 'SecurityBadCertificateError';
        break;
      case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
        errName = 'SecurityUnsupportedCertificateTypeError';
        break;
      case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
        errName = 'SecurityUnsupportedTLSVersionError';
        break;
      case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
        errName = 'SecurityCertificateDomainMismatchError';
        break;
      default:
        errName = 'SecurityError';
        break;
      }
    }
  } else {
    errType = 'Network';
    switch (status) {
      // connect to host:port failed
    case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
      errName = 'ConnectionRefusedError';
      break;
      // network timeout error
    case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
      errName = 'NetworkTimeoutError';
      break;
      // hostname lookup failed
    case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
      errName = 'DomainNotFoundError';
      break;
    case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
      errName = 'NetworkInterruptError';
      break;
    default:
      errName = 'NetworkError';
      break;
    }
  }

  // XXX we have no TCPError implementation right now because it's really hard to
  // do on b2g18. On mozilla-central we want a proper TCPError that ideally
  // sub-classes DOMError. Bug 867872 has been filed to implement this and
  // contains a documented TCPError.webidl that maps all the error codes we use in
  // this file to slightly more readable explanations.

  try {
    let error = Cc["@mozilla.org/dom-error;1"].createInstance(Ci.nsIDOMDOMError);
    error.wrappedJSObject.init(errName);
    error.layer = errType;
    return error;
  } catch (e) {
    dump("Error creating DOMError: " + e + "\n");
  }

  return { name: errName, layer: errType };
}

function analyzeSecurityInfo(xhr, error, hostname) {
  dump("\n" + hostname + ": ");
  if (error) {
    dump("failed: " + error.name + "(" + error.layer + ")\n");
  } else {
    dump("succeeded\n");
  }
  if (!xhr) {
    dump("\tRequest failed: no information available\n");
    return false;
  }

  let isEV = false;
  try {
    let channel = xhr.channel;
    let secInfo = channel.securityInfo;
    // Print general connection security state

    dump("Security Info:\n");
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
      secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
      dump("\tSecurity state: ");
      // Check security state flags
      if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) ===
          Ci.nsIWebProgressListener.STATE_IS_SECURE) {
        dump("secure\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) ===
                 Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
        dump("insecure\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) ===
                 Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
        dump("unknown\n");
        dump("\tSecurity description: " + secInfo.shortSecurityDescription + "\n");
        dump("\tSecurity error message: " + secInfo.errorMessage + "\n");
      }
    } else {
      dump("\tNo security info available for this channel\n");
    }

    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLStatusProvider) {
      let cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider)
        .SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

      isEV = secInfo.QueryInterface(Ci.nsISSLStatusProvider)
       .SSLStatus.QueryInterface(Ci.nsISSLStatus)
       .isExtendedValidation;

      dump("\tCommon name (CN) = " + cert.commonName + "\n");
      dump("\tOrganisation = " + cert.organization + "\n");
      dump("\tIssuer = " + cert.issuerOrganization + "\n");
      dump("\tSHA1 fingerprint = " + cert.sha1Fingerprint + "\n");

      let validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
      dump("\tValid from " + validity.notBeforeGMT + "\n");
      dump("\tValid until " + validity.notAfterGMT + "\n");
      dump("\n\n");
    }
  } catch(err) {
    dump("\nError: " + err.message + "\n");
  }
  return isEV;
}


function RedirectStopper() {}

RedirectStopper.prototype = {
  // nsIChannelEventSink
  asyncOnChannelRedirect: function(oldChannel, newChannel, flags, callback) {
    throw Cr.NS_ERROR_ENTITY_CHANGED;
  },

  getInterface: function(iid) {
    return this.QueryInterface(iid);
  },
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIChannelEventSink])
};


// make a minimal XHR request to the identified host and record details of the attempt
function queryHost(hostname, callback) {
  let timeout = Timer.setTimeout(() => completed(UNKNOWN_ERROR), REQUEST_TIMEOUT);
  function completed(error, req) {
    if (timeout) {
      Timer.clearTimeout(timeout);
      timeout = null;
      callback(error, req);
    }
  }

  function errorHandler(e) {
    completed(e.target.channel.QueryInterface(Ci.nsIRequest).status, e.target);
  }

  function readyHandler(e) {
    if (e.target.readyState === 4) {
      completed(null, e.target); // no error
    }
  }

  try {
    let req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
      .createInstance(Ci.nsIXMLHttpRequest);
    req.open("HEAD", "https://" + hostname, true);

    req.timeout = REQUEST_TIMEOUT;
    req.channel.notificationCallbacks = new RedirectStopper();
    req.addEventListener("error", errorHandler, false);
    // note: onreadystatechange fires BEFORE the error handler
    // so we need to watch for "load" instead
    // otherwise, we assume success when it's really an error
    // (what an intuitive spec...: http://www.w3.org/TR/XMLHttpRequest/#request-error
    req.addEventListener("load", readyHandler, false);
    req.send();
  } catch (err) {
    dump("ERROR: exception making request to " + hostname + ": " + err + "\n");
    completed(UNKNOWN_ERROR);
  }
}

// write a single entry to the log output stream
function writeToErrorLog(outputStream, hostname, error) {
  let message = "0x" + error.toString(16);
  if ((error & 0xff0000) === 0x5a0000) { // Security module
    message = message + " " + nssErrorsService.getErrorMessage(error);
  }
  message = hostname + " " + message;
  message = message.replace("\n", "|", "g").replace("\r", "", "g") + "\n";
  outputStream.write(message, message.length);
}

function writeToLog(data, errorStream, evStream) {
  if (data.error) {
    writeToErrorLog(errorStream, data.name, data.error);
  }
  if (data.ev) {
    evStream.write(data.name, data.name.length);
  }
}

// This function iterates through the provided list of hosts
// generating an XHR to each and recording the results in the
// provided output stream
function processAllHosts(hosts, errorStream, evStream) {

  // Here we track outstanding itemsresults.  These are added to the outstanding
  // list in the order that they appear in the input file so they can be output
  // in the same order.  Values that appear out of order are saved until all
  // items before them are finished.
  let outstanding = [];
  function flushOutstanding() {
    while (outstanding.length > 0 && (outstanding[0].error || outstanding[0].ev)) {
      writeToLog(outstanding.shift(), errorStream, evStream);
    }
  }
  let counter = 0;
  let errorCount = 0;
  let evCount = 0;
  let doneCount = 0;
  function recordResult(hostname, error, xhr) {
    let errorInfo = error ? createTCPError(error) : null;
    let ev = analyzeSecurityInfo(xhr, errorInfo, hostname);

    ++doneCount;
    if (error) {
      ++errorCount;
    }
    if (ev) {
      ++evCount;
    }

    let idx = outstanding.findIndex(e => e.name === hostname);
    let entry = outstanding[idx];
    outstanding.splice(idx, 1);

    entry.error = error;
    entry.ev = ev;
    writeToLog(entry, errorStream, evStream);
  }

  function startNext() {
    let host;

    function handleResult(err, xhr) {
      if (err && host.retries > 0) {
        --host.retries;
        queryHost(host.name, handleResult);
        return;
      }

      recordResult(host.name, err, xhr);
      dump("Done/Errors/EV/Remaining: " +
           doneCount + " / " + errorCount + " / " + evCount + " / " +
           (hosts.length-doneCount) + "+" + outstanding.length +
           "(" + ((outstanding.length > 0) ? outstanding[0].name : "-") + ")\n");

      startNext();
    }

    if (counter < hosts.length) {
      host = { name: hosts[counter++], retries: MAX_RETRIES };
      outstanding.push(host);
      queryHost(host.name, handleResult);
    }
  }

  for (let i = 0; i < MAX_CONCURRENT_REQUESTS; ++i) {
    startNext();
  }

  waitForAResponse(() => outstanding.length > 0);
}

// Since all events are processed on the main thread, and since event
// handlers are not preemptible, there shouldn't be any concurrency issues.
function waitForAResponse(condition) {
  // From <https://developer.mozilla.org/en/XPConnect/xpcshell/HOWTO>
  try {
    let threadManager = Cc["@mozilla.org/thread-manager;1"]
      .getService(Ci.nsIThreadManager);
    let mainThread = threadManager.currentThread;
    while (condition()) {
      mainThread.processNextEvent(true);
    }
  } catch(e) {
    dump("\nthread issue\n"); // temp debug code
  }
}

function openFile(name) {
  let file = FileUtils.getFile("CurWorkD", [name]);
  let fos = FileUtils.openSafeFileOutputStream(file);
  dump("Opened " + name + " for output\n");
  return fos;
}


// ****************************************************************************
// Kick off the whole process
// get the status of each host
// download and parse the raw text file
let hosts = downloadHosts();
try {
  dump("Loaded " + hosts.length + " hosts\n");
  let errFile = openFile(ERROR_OUTPUT);
  let evFile = openFile(EV_OUTPUT);
  processAllHosts(hosts, errFile, evFile);
  FileUtils.closeSafeFileOutputStream(errFile);
  FileUtils.closeSafeFileOutputStream(evFile);
} catch (e) {
  dump("ERROR: problem writing output\n");
}
// ****************************************************************************

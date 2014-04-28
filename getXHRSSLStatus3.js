// TO BE USED FOR mozilla::pkix COMPAT TESTING


/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// How to run this file:
// 1. [obtain firefox source code]
// 2. [build/obtain firefox binaries]
// 3. run `[path to]/run-mozilla.sh [path to]/xpcshell \
//                                  [path to]/getXHRSSLStatus2.js \

// <https://developer.mozilla.org/en/XPConnect/xpcshell/HOWTO>
// <https://bugzilla.mozilla.org/show_bug.cgi?id=546628>

/*
/Users/mwobensmith/fx31/build/unix/run-mozilla.sh /Users/mwobensmith/fx31/objdir-ff/dist/bin/xpcshell /Users/mwobensmith/Desktop/pkix_testing/getXHRSSLStatus3.js

*/


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


const SOURCE = "test_domains.txt";
const OUTPUT = "errorDomains_ocsp.txt";

// set OCSP pref to either true or false
Services.prefs.setBoolPref("security.OCSP.require", true);


const MINIMUM_REQUIRED_MAX_AGE = 60 * 60 * 24 * 7 * 18;
const MAX_CONCURRENT_REQUESTS = 10;
const MAX_RETRIES = 0;
const REQUEST_TIMEOUT = 30 * 1000;



let totalHosts = 0;
let errorHosts = [];
let evHosts = [];

var errorTable = {
2153390069:"SEC_ERROR_EXPIRED_CERTIFICATE",
2153390067:"SEC_ERROR_UNKNOWN_ISSUER",
2152398861:"NS_ERROR_CONNECTION_REFUSED",
2153394151:"SSL_ERROR_RX_RECORD_TOO_LONG",
2153394164:"SSL_ERROR_BAD_CERT_DOMAIN",
2153390060:"SEC_ERROR_UNTRUSTED_ISSUER",
2152398878:"NS_ERROR_UNKNOWN_HOST",
2153390050:"SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE",
2152398919:"NS_ERROR_NET_INTERRUPT",
2153389904:"SECURITY",
2152398868:"NS_ERROR_NET_RESET",
2153389937:"SEC_ERROR_UNRECOGNIZED_OID",
2153390068:"SEC_ERROR_REVOKED_CERTIFICATE",
2153390044:"SEC_ERROR_CA_CERT_INVALID",
2153394070:"SSL_ERROR_UNRECOGNIZED_NAME_ALERT",
2147500037:"NS_ERROR_FAILURE",
2153389942:"SEC_ERROR_REUSED_ISSUER_AND_SERIAL",
2153394174:"SSL_ERROR_NO_CYPHER_OVERLAP",
2152398862:"NS_ERROR_NET_TIMEOUT",
2153389954:"SEC_ERROR_OCSP_UNKNOWN_CERT",
2153394076:"SSL_ERROR_INTERNAL_ERROR_ALERT",
2147500036:"NS_ERROR_ABORT",
2153394159:"SSL_ERROR_BAD_CERT_ALERT"
}


function download() {
  let file = Cc["@mozilla.org/file/directory_service;1"]
    .getService(Components.interfaces.nsIProperties)
    .get("CurWorkD", Components.interfaces.nsILocalFile);
  file.append(SOURCE);
  let stream = Cc["@mozilla.org/network/file-input-stream;1"]
                 .createInstance(Ci.nsIFileInputStream);
  stream.init(file, -1, 0, 0);
  let buf = NetUtil.readInputStreamToString(stream, stream.available());
  let masterArray = buf.split("\n");

  var domainArray = [];
  var l = masterArray.length;
  for ( var i=0;i<l;i++ )
  {
    domainArray.push ( {name:masterArray[i], retries:MAX_RETRIES} );
  }
  return domainArray;
}


function getHosts() {
  var tempHosts = download();
  totalHosts = tempHosts.length;
  return tempHosts;
}


function createTCPErrorFromFailedXHR(xhr,uri) {
  let status = xhr.channel.QueryInterface(Ci.nsIRequest).status;

  try {
     errorHosts.push ( errorTable[status] + " " + uri );
  } catch (e) {
     errorHosts.push ( "UNKNOWN " + uri );
  }

// debug - some errors are still unknown
if ( errorTable[status] == undefined ) errorHosts.push (status);


  let errType;
  if ((status & 0xff0000) === 0x5a0000) { // Security module
    const nsINSSErrorsService = Ci.nsINSSErrorsService;
    let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
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
      let nssErr = Math.abs(nsINSSErrorsService.NSS_SEC_ERROR_BASE)
                       - (status & 0xffff);
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
      let sslErr = Math.abs(nsINSSErrorsService.NSS_SSL_ERROR_BASE)
                       - (status & 0xffff);
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
  return error;
  } catch (e) {
  return null; // something bad happened
  }
 
  // XXX: errType goes unused
}

function dumpSecurityInfo(xhr, error, uri) {
  let channel = xhr.channel;
  dump("\n++++++++++++\n\n");
  try {
    dump("Connection status: ");
    if (error == null) {
      dump("succeeded\n");
    } else {
      dump("failed: " + error.name + "\n");
    }
 
    dump("Site: " + uri + "\n" );
    let secInfo = channel.securityInfo;
    // Print general connection security state

    dump("Security Info:\n");
    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
      secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
      dump("\tSecurity state: ");
        // Check security state flags
    if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
           == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
      dump("secure\n");
    } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE)
           == Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
      dump("insecure\n");
    } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN)
               == Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
      dump("unknown\n");
      dump("\tSecurity description: " + secInfo.shortSecurityDescription + "\n");
      dump("\tSecurity error message: " + secInfo.errorMessage + "\n");
    }
    } else {
      dump("\tNo security info available for this channel\n");
    }

    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLStatusProvider) {
      var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider)
                        .SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

      var isEV = secInfo.QueryInterface(Ci.nsISSLStatusProvider)
       .SSLStatus.QueryInterface(Ci.nsISSLStatus)
       .isExtendedValidation;

      if ( isEV )
      {
	evHosts.push (uri);
      }
            
      dump("\tCommon name (CN) = " + cert.commonName + "\n");
      dump("\tOrganisation = " + cert.organization + "\n");
      dump("\tIssuer = " + cert.issuerOrganization + "\n");
      dump("\tSHA1 fingerprint = " + cert.sha1Fingerprint + "\n");
       
      var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
      dump("\tValid from " + validity.notBeforeGMT + "\n");
      dump("\tValid until " + validity.notAfterGMT + "\n");
      dump("\n\n");
    }
  } catch(err) {
    dump("\nError: " + err.message + "\n");
  }
}


function RedirectStopper() {};

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

function getXHRSSLStatus(host, resultList) {
  var req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
            .createInstance(Ci.nsIXMLHttpRequest);
  var inResultList = false;
  var uri = "https://" + host.name;
  try {
    req.open("GET", uri, true);
  } catch (e) {
    dump ( "Error opening uri: " + e + "\n" );
    resultList.push(req);
    return;
  }
  req.timeout = REQUEST_TIMEOUT;
  req.channel.notificationCallbacks = new RedirectStopper();
  req.addEventListener("error", 
			function(e){
      			inResultList = true;
      			resultList.push(req); 
			 var error = createTCPErrorFromFailedXHR(req,uri);
			 dumpSecurityInfo(req, error, uri);
			},
			false);
  req.onreadystatechange = function(event) {
    if (!inResultList && req.readyState == 4 ) {
      dumpSecurityInfo(req, null, uri); 
      inResultList = true;
      resultList.push(req); 
    }
  };

  try {
    req.send();
  }
  catch (e) {
    dump("ERROR: exception making request to " + host.name + ": " + e + "\n");
  }
}


function getXHRSSLStatuses(inHosts, outStatuses) {
  var expectedOutputLength = inHosts.length;
  var tmpOutput = [];
  for (var i = 0; i < MAX_CONCURRENT_REQUESTS && inHosts.length > 0; i++) {
    var host = inHosts.shift();
    getXHRSSLStatus(host, tmpOutput);
  }

  while (outStatuses.length != expectedOutputLength) {
    waitForAResponse(tmpOutput);
    var response = tmpOutput.shift();
    outStatuses.push(response);
dump ( "\noutStatuses.length: " + outStatuses.length + "\n" );
dump ( "inHosts.length: " + inHosts.length + "\n");
    if (inHosts.length > 0) {
      var host = inHosts.shift();
//      dump("spinning off request to '" + host.name + "' (remaining retries: " +
//           host.retries + ")\n");
      	getXHRSSLStatus(host, tmpOutput);
    }
  }
}

// Since all events are processed on the main thread, and since event
// handlers are not preemptible, there shouldn't be any concurrency issues.
function waitForAResponse(outputList) {
  // From <https://developer.mozilla.org/en/XPConnect/xpcshell/HOWTO>

try {
  var threadManager = Cc["@mozilla.org/thread-manager;1"]
                      .getService(Ci.nsIThreadManager);
  var mainThread = threadManager.currentThread;
  while (outputList.length == 0) {
    mainThread.processNextEvent(true);
  }
} catch (e) {
dump ("\nthread issue\n"); // temp debug code
}
}




function writeTo(string, fos) {
  fos.write(string, string.length);
  dump (string);
}


function output() {
  dump ("\nTest over.\n");
  dump ("\nTotal failures: " + errorHosts.length + "\n");
  try {
    errorHosts.sort();
    var file = FileUtils.getFile("CurWorkD", [OUTPUT]);
    var fos = FileUtils.openSafeFileOutputStream(file);
    writeTo("Total failures: " + errorHosts.length + "\n", fos);
    for ( var i=0;i<errorHosts.length;i++ ) {
        writeTo(errorHosts[i] + "\n", fos)
    }


    evHosts.sort();
    writeTo("\n\nTotal EV hosts: " + evHosts.length + "\n", fos);
    for ( var i=0;i<evHosts.length;i++ ) {
        writeTo(evHosts[i] + "\n", fos)
    }

    FileUtils.closeSafeFileOutputStream(fos);
  }
  catch (e) {
    dump("ERROR: problem writing output to '" + OUTPUT + "': " + e + "\n");
  }
}

// ****************************************************************************
// This is where the action happens:
// download and parse the raw text file 
var hosts = getHosts();
// get the status of each host
var sslStatuses = [];
getXHRSSLStatuses(hosts, sslStatuses);
output();
// ****************************************************************************

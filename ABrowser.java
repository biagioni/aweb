// Author: Edoardo Biagioni, esb@hawaii.edu, 2026

public class ABrowser extends javax.swing.JFrame
{
  // data to display
  String currentUrl = "";   // the currently displayed url
  String currentHtml = "";  // the currently displayed content
  String backUrl = "";      // pressing the back link brings you here

  String welcomeHtml =
      // "<html>\n<style> body { font-size: 2em; } </style>\n" +
      "<html>\n" +
      "<body><h1>Welcome to the Asynchronous Browser!</h1>\n" +
      "</div></body></html>\n";
// to do: increase size of text box and select.  My attempts so far have failed
  String urlForm =
      "<hr><br>" +
      "<form method='post' action='https://localhost/go.html' style='font-size:30px;'>" +
      "Enter URL: " +
      "<select name='protocol' style='height:30px;'>\n" +
      "<option value='https'>https</option>" +
      "<option value='http'>http</option>" +
      "</select>" +
      "<input name='url'>\n" +
      "<input type='submit' value='Go'>\n" +
      "</form>";
  String futureWork =
      "<hr><br>" +
      "This is a demonstration client for " +
      "the asynchronous web protocol AWeb.  " +
      "It is not intended to be used for serious web access.  " +
      "Missing features include: " +
      "correct verification of certificates, " +
      "the ability to reload and delete cached web pages, " +
      "and the URL entry box being too small.  " +
      "Many more bugs are likely present.";

  // this protocol always uses port 1480, unless the URL indicates otherwise
  final int asyncWebPort = 1480;
  // an AES key has 256 bits, which is 32 bytes
  final int sessionKeySize = 32;
  // a nonce always has 16 bytes, and is used as the IV for encryption
  final int nonceSize = 16;
  // an http request has a URL in the usual http header
  // an http reply comes back with a URL and a content
  // an https request has the host name in the clear, and encrypted:
  // http-like URL (path and host), nonce, and session key for the reply
  // an https reply comes back with an unencrypted nonce and
  // encrypted URL and content
  // in the "requested" data structures the String is a URL,
  java.util.Map<String, java.net.InetAddress> dns = new java.util.HashMap<>();
  java.util.Set<String> requestedHttp = new java.util.HashSet<>();

  // the nonce is a 128-bit (16 byte) integer
  private class Nonce implements java.io.Serializable {
    byte[] value;
    private Nonce() {
      value = new byte[nonceSize];
      random.nextBytes(value);  // create and save session nonce
      if (value[0] == 0) {      // make sure the first byte is nonzero
        value[0] = 1;
      }
    }
    private Nonce(byte[] bytes) {
      value = new byte[nonceSize];   // initially all 0
      System.arraycopy(bytes, 0, value, 16 - bytes.length, bytes.length);
    }
    public boolean equals(Object obj) {
      if (obj instanceof Nonce) {
        Nonce n = (Nonce) obj;
        for (int i = 0; i < value.length; i++) {
          if (value[i] != n.value[i]) {
            return false;
          }
        }
        return true;
      }
      return false;
    }
    public int hashCode() {    // needed because we use HashMap
      int result = 0;
      for (byte b: value) {
        result += b;
      }
      return result;
    }
    public String toString() {
      return java.util.HexFormat.of().formatHex(value);
    }
    // needed for Serializable
    private void writeObject(java.io.ObjectOutputStream out)
         throws java.io.IOException {
      out.write(value);
    }
    private void readObject(java.io.ObjectInputStream in)
         throws java.io.IOException, ClassNotFoundException {
      value = new byte[nonceSize];
      in.read(value, 0, nonceSize);
    }
    private void readObjectNoData()
         throws java.io.ObjectStreamException {
      value = new byte[nonceSize];   // all zeros
    }
  }
  private class HttpsRequest implements java.io.Serializable {
    String url;
    byte[] sessionkey;
    private void writeObject(java.io.ObjectOutputStream out)
         throws java.io.IOException {
      out.writeObject(url);
      out.write(sessionkey);
    }
    private void readObject(java.io.ObjectInputStream in)
         throws java.io.IOException, ClassNotFoundException {
      url = (String)in.readObject();
      sessionkey = new byte[sessionKeySize];
      in.read(sessionkey, 0, sessionKeySize);
    }
    private void readObjectNoData()
         throws java.io.ObjectStreamException {
      url = "no URL";
      sessionkey = new byte[sessionKeySize];
    }
    // printing session keys is insecure, so only show a checksum modulo 1000
    // 0.1% of different session keys will have the same checksum
    public String toString() {
      int total = 0;
      if (sessionkey != null) {
        for (byte b: sessionkey) {
          total += ((int)b + 256) % 256;
        }
      }
      return url + ", session key sum "+ (total % 1000);
    }
  }
  java.util.Map<Nonce, HttpsRequest> requestedHttps = new java.util.HashMap<>();

  // cachedUrls is the URLs of all the files we have cached
  java.util.List<String> cachedUrls = new java.util.LinkedList<>();

  // files for persistent storage of our values
  String stateFileName = "aweb.state";

  // display variables
  javax.swing.JEditorPane page = null;
  javax.swing.JScrollPane scroll = null;

  // random number generator for nonces
  java.security.SecureRandom random = new java.security.SecureRandom();

  // communicating with mkhtml on this port -- why even have mkhtml?
  // final int port = 22793;

  enum addRemove { add, remove };

  /* addRemoveRequest is synchronized because the underlying collection
     (HashSet or HashMap) is not necessarily synchronized.
     As long as all adds and removes happen by calling this method,
     they will be consistent no matter how many threads try to modify
     the collection at the same time.
     sessionkey is filled in with the value of any pre-existing session key,
     or saved if there is no pre-existing https record
   */
  // returns true if successfully added/removed, false otherwise
  private synchronized boolean
      addRemoveRequest(addRemove op, String url, Nonce nonce,
                       byte[] sessionkey) {
    boolean https = url.substring(0, 5).equalsIgnoreCase("https"); 
    if (op == addRemove.add) {
      if (https) {
        if (nonce == null) {
          System.out.println("aRR add: null nonce");
          return false;
        }
        HttpsRequest value = requestedHttps.get(nonce);
        if (value != null) {  // fill in the session key
          System.arraycopy(value.sessionkey, 0, sessionkey, 0, sessionKeySize); 
          return false;
        }
        value = new HttpsRequest();
        value.url = url;
        value.sessionkey = new byte[sessionKeySize];
        random.nextBytes(value.sessionkey);  // create and save session key
System.out.println("aRR: set value to " + value);
        System.arraycopy(value.sessionkey, 0, sessionkey, 0, sessionKeySize); 
        return requestedHttps.put(nonce, value) == null;
      } else {    // http
        return requestedHttp.add(url);
      }
    } else if (op == addRemove.remove) {
      if (https) {
        if (nonce == null) {
          System.out.println("aRR remove: null nonce");
          return false;
        }
        HttpsRequest value = requestedHttps.get(nonce);
        if (value == null) {
          System.out.println("got response for not requested nonce " + nonce);
          return false;
        }
        System.arraycopy(value.sessionkey, 0, sessionkey, 0, sessionKeySize); 
        return (requestedHttps.remove(nonce) != null);
      } else {     // http
        return (requestedHttp.remove(url) ||
                   // url may have a :1480, which should be ignored
                requestedHttp.remove(url.replaceFirst(":" + asyncWebPort, "")));
      }
    } else {
      System.out.println("unknown addRemove " + op);
      throw new RuntimeException("unimplemented op in addRemoveUrl");
    }
  }

  private class Handler extends java.lang.Thread {
    java.net.DatagramSocket sock = null;

    // constructor
    public Handler(java.net.DatagramSocket sock) {
      this.sock = sock;
    }

    private class ParseResult {
      public boolean success;  // other fields only valid if this is true
      public boolean is_cert;  // for certs only cert and host valid
      public String host;      // only for certs
      public String cert;      // only for certs
      public boolean secure;   // true for https, false for http
      public String url;       // only for http requests
      public Nonce nonce;      // only for https requests
      public byte[] content;   // for both
    }

    private ParseResult parsePacket(byte[] packet) {
      ParseResult result = new ParseResult();
      result.success = false;
      if (packet.length <= 0) {
        System.out.println("pP: illegal response length " + packet.length);
        return result;
      }
      int charIndex = 1;
      for (; charIndex < packet.length && packet[charIndex] != 0; charIndex++) {
      }
      if (charIndex >= packet.length) {
        System.out.println("pP: no null byte completing url/nonce");
        return result;
      }
      if (charIndex < 2) {
        System.out.println("pP: no URL included in response");
        return result;
      }
      String urlNonce = new String(packet, 1, charIndex - 1);
      System.out.println("pP: url/nonce/domain is " + urlNonce);
      byte[] data = java.util.Arrays.copyOfRange(packet, charIndex + 1,
                                                 packet.length);
      if (packet[0] == 3) {                                // certificate
        result.success = true;
        result.is_cert = true;
        result.host = urlNonce;
        result.cert = new String(data);
      } else if ((packet[0] == 1) || (packet[0] == 2)) {   // http or https
        result.success = true;
        result.is_cert = false;
        result.secure = (packet[0] == 2);                  // https
System.out.println("urlNonce is " + urlNonce);
        result.url = (result.secure ? "https" : urlNonce);
        result.nonce = null;
        if (result.secure) {
          java.util.HexFormat hex = java.util.HexFormat.of();
          result.nonce = new Nonce(hex.parseHex(urlNonce));
        }
        result.content = data;
        // printBytes(data, "pP data");
        return result;
      }
      return result;
    }

    private boolean certMatch(String host, String name, String cert,
                              java.security.cert.X509Certificate x509) {
      if (name.equalsIgnoreCase(host)) {   // found!
        System.out.println("certMatch found requested name " + name);
        // the replacement string should be the same as on the server
        String fname = "certs/" + host.replaceAll("[\\/:*?<>| ]+", "");
System.out.println("received cert, writing file " + fname);
        if (writeFile(fname, cert.getBytes())) {
          return true;
        }
        System.out.println("unable to save cert " + fname);
      } else {
        System.out.println("name " + name + " does not match host " + host);
      }
      return false;
    }

    private boolean saveCert(String host, String cert) {
      System.out.println("received certificate response for host " + host);
      boolean certForReq = false;
      try {
        java.security.cert.CertificateFactory cf =
          java.security.cert.CertificateFactory.getInstance("X.509");
        java.io.ByteArrayInputStream stream =
          new java.io.ByteArrayInputStream(cert.getBytes());
        java.util.List<java.security.cert.X509Certificate> certs =
          new java.util.LinkedList<>();
        while (stream.available() > 0) {
          java.security.cert.Certificate crt = cf.generateCertificate(stream);
          if (crt instanceof java.security.cert.X509Certificate) {
            java.security.cert.X509Certificate x509 =
              (java.security.cert.X509Certificate) crt;
            // System.out.println("cert is " + x509);
            try {
              x509.checkValidity();   // check that the dates are still good
// to do: checkValidity does not stop self-signed certificates
            } catch (java.security.cert.CertificateException exn) {
              System.out.println("invalid cert " + x509);
              return false;           // do not accept certs w/ invalid dates
            }
            certs.add(x509);          // see if it matches the requested host
          } else {   // not an x509 certificate
            System.out.println("invalid certificate " + crt);
            return false;    // not sure what the right thing to do is here
          }
        }
        for (java.security.cert.X509Certificate x509: certs) {
//        String fullName = x509.getSubjectDN().getName();
          String fullName = x509.getSubjectX500Principal().getName();
          System.out.println(" name is " + fullName);
//        System.out.println(" class is " + x509.getSubjectDN().getClass());
          System.out.println(" class is " + x509.getSubjectX500Principal().getClass());
          String cn = null;
          // amazingly, I wasn't able to find a good library to parse this
          int cnIndex = fullName.indexOf("CN=");
          if (cnIndex != -1) {
            int endIndex = fullName.indexOf(',', cnIndex);
            if (endIndex != -1) {
              cn = fullName.substring(cnIndex + 3, endIndex);
            } else {
              cn = fullName.substring(cnIndex + 3);
            }
            System.out.println(" CN is " + cn);
            if (certMatch(host, cn, cert, x509)) {
              return true;
            }
          }   // canonical name, CN, did not match, try the altnames
          java.util.Collection<java.util.List<?>>
             altnames = x509.getSubjectAlternativeNames();
          System.out.println("altnames are " + altnames);
          if (altnames != null) {
            for (java.util.List<?> altname: altnames) {
// https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/cert/X509Certificate.html#getSubjectAlternativeNames()
              if ((Integer)altname.get(0) == 2) {  // DNS name
                String dnsName = (String)altname.get(1);
                if (certMatch(host, dnsName, cert, x509)) {
                  System.out.println("found requested altname " + dnsName);
                  return true;
                }
              } else {     //
                System.out.println("strange altname type " + altname.get(0));
                System.out.println("altname is " + altname);
              }
            }    // end loop over altnames
          }      // else no altnames.  Since CN doesn't match, fail
        }
        System.out.println("certificate does not have name " + host);
      } catch (java.security.cert.CertificateException e) {
        System.out.println("creating certificate path gave " + e);
      }
      return false;
    }

    private void saveAndDisplay(String url, byte[] content) {
      // save the response with a back button
      String sanitized = url.replaceAll("[^\\w]+", "_");
      System.out.println("sanitized URL is " + sanitized);
      // turn https_www_example_com into https/www_example_com
      String fname = sanitized.replaceFirst("[_]", "/");
      String contentS = new String(content);
      String modifiedContent = makeContent(contentS, url);
System.out.println("received content, writing file " + fname);
      if (writeFile(fname, removeHTTPResponseHeader(contentS).getBytes())) {
        currentUrl = homePage() + "/" + fname;
        currentHtml = modifiedContent;
        cachedUrls.add(currentUrl);
        saveState();
      } else {
        System.out.println("error writing " + fname);
      }
    }

    private static java.security.PublicKey getPubKey(String host) {
      // the replacement string should be the same as on the server
      String fname = "certs/" + host.replaceAll("[\\/:*?<>| ]+", "");
      try {
        java.io.FileInputStream stream = new java.io.FileInputStream(fname);
        java.security.cert.CertificateFactory cf =
          java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate crt = cf.generateCertificate(stream);
        if (! (crt instanceof java.security.cert.X509Certificate)) {
          System.out.println("found non-x509 certificate: " + crt);
          return null;
        }
        java.security.cert.X509Certificate x509 =
          (java.security.cert.X509Certificate) crt;
        try {
          x509.checkValidity();       // check that the dates are still good
          return x509.getPublicKey(); // the only successful return in getPubKey
        } catch (java.security.cert.CertificateException e) {
          System.out.println("getting public key from " + fname + " gave " + e);
        }
      } catch (java.security.cert.CertificateException e) {
        System.out.println("unable to get x509 certificate factory " + e);
      } catch (java.io.IOException e) {
        System.out.println("unable to open certificate file " + fname);
      }
      return null;
    }

    private void handleData(byte[] packet) {
      // String desc = "received (" + packet.length + " bytes)";
      // printBytes(packet, desc);
      if (packet.length <= 6) {
        System.out.println("illegal response length " + packet.length);
        return;
      }
      ParseResult pr = parsePacket(packet);
      if (! pr.success) {
        System.out.println("unable to parse packet");
        return;
      }
      if (pr.is_cert) {                 // certificate
        if (! saveCert(pr.host, pr.cert)) {
          System.out.println("unable to save certificate for " + pr.host);
          return;
        }
        java.security.PublicKey pubkey = getPubKey(pr.host);
        if (pubkey == null) {
          System.out.println("error: no public key for " + pr.host);
          return;
        }
// now that we have the key, send all matching pending requests
        for (Nonce nonce: requestedHttps.keySet()) {
          HttpsRequest req = requestedHttps.get(nonce);
          String noScheme = req.url.substring("https://".length());
          int endIndex = noScheme.indexOf('/');
          String host = ((endIndex == -1) ? noScheme :
                                            noScheme.substring(0, endIndex));
          // System.out.println("comparing host " + pr.host + " to " + host);
          if (host.equalsIgnoreCase(pr.host)) {
            // System.out.println("host " + pr.host + " equals " + host);
            try {
              java.net.URI uri = new java.net.URI(req.url);
              java.net.URL url = uri.toURL();
              // System.out.println("url has host " + url.getHost());
              if (url.getHost().equalsIgnoreCase(pr.host)) {  // matching
                // System.out.println("sending request for host " + url.getHost() + ", nonce is " + nonce);
                sendRequest(url, nonce, pubkey, req.sessionkey, sock);
              }
            } catch (java.net.URISyntaxException e) {
              System.out.println("error: ignoring uri " + pr.url);
            } catch (java.net.MalformedURLException e) {
              System.out.println("error: ignoring url " + pr.url);
            }
          }
        }
      } else if (pr.secure) {          // https URL
        System.out.println("received https response for nonce " + pr.nonce);
        byte[] sessionkey = new byte[sessionKeySize];
        HttpsRequest req = requestedHttps.get(pr.nonce);
        if (req != null) {
          pr.url = req.url;          // otherwise pr.url is just "https"
        } else {                     // not a problem, someone else's nonce
          System.out.println("ok: received " + pr.nonce + " but no match");
          System.out.print("keys are: ");
          for (Nonce n: requestedHttps.keySet()) {
            System.out.print(n + ", ");
          }
          System.out.println();
          return;                    // nothing left to do
        }
        byte[] plaintext = null;
        if (addRemoveRequest(addRemove.remove, pr.url, pr.nonce, sessionkey)) {
          System.out.println("received https response for URL " + pr.url +
                             " and nonce " + pr.nonce);
          printBytes(sessionkey, "session key");
          javax.crypto.Cipher cipher = null;
          javax.crypto.spec.GCMParameterSpec spec = null;
          java.security.Key key = null;
// getinstance may throw NoSuchAlgorithmException
          try {
            cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
          } catch (Exception e) {
            System.out.println("getInstance throwing " + e);
          }
          spec = new javax.crypto.spec.GCMParameterSpec(128, pr.nonce.value);
          key = new javax.crypto.spec.SecretKeySpec(sessionkey, "AES");
// cipher.init may throw InvalidKeyException
          try {
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec);
          } catch (Exception e) {
            System.out.println("cipher.init throwing " + e);
          }
// cipher.doFinal may throw IllegalBlockSizeException
          try {
            plaintext = cipher.doFinal(pr.content);
          } catch (Exception e) {
            System.out.println("cipher.doFinal throwing " + e);
          }
        } else {
          System.out.println("got response for unrequested " + pr.url);
        }
        if (plaintext == null) {
          System.out.println("no plaintext");
          return;
        }
        try {
          System.out.println("plaintext " + new String(plaintext));
        } catch (Exception e) {
          System.out.println("new String from bytes throwing " + e);
        }
        pr.content = plaintext;
        System.out.println("url is " + pr.url);
        saveAndDisplay(pr.url, plaintext);
      } else {                   // http URL
        System.out.println("received http response for URL " + pr.url);
        String modifiedContent = "";
        if (addRemoveRequest(addRemove.remove, pr.url, null, null)) {
          // we expected this url, save the response with a back button
          saveAndDisplay(pr.url, pr.content);
        } else {
          System.out.println("response to non-requested URL " + pr.url);
          System.out.println("http requests are " + requestedHttp);
          System.out.println("https requests are " + requestedHttps);
        }
      }
    }  // end handleData

    // main loop
    public void receiveLoop() {
      byte[] replyData = new byte[65536];
      java.net.DatagramPacket reply = 
         new java.net.DatagramPacket(replyData, replyData.length);
      while(true) {
        try {
          // sock.setSoTimeout(10000);
          sock.receive(reply);
          handleData(java.util.Arrays.copyOf(replyData, reply.getLength()));
        } catch (java.net.SocketTimeoutException e) {
          System.out.println("oo request timed out");
        } catch (java.io.IOException e) {
          System.out.println("receive throws " + e);
        }
      }
    }

    public void run() {   // main method of the thread
      receiveLoop();
    }
  }   // end inner class Handler

  private char hexValue(String hex /* char c1, char c2 */ ) {
    return (char) Integer.parseUnsignedInt(hex, 16);
  }

  private String sanitizeFormData(String data) {
    System.out.println("original data: '" + data + "'");
    int index = data.indexOf('+');
    while (index != -1) {          // replace + with blank
      data = data.substring(0, index) + " " + data.substring(index + 1);
      index = data.indexOf('+');   // replace next
    }
    System.out.println("intermediate data: '" + data + "'");
    index = data.indexOf('%');
    while (index != -1) {
      if (index + 3 > data.length()) {
        System.out.println("error, % not followed by two hex: '" + data + "'");
      }
      data = data.substring(0, index) +
             // hexValue(data.charAt(index + 1), data.charAt(index + 2)) +
             hexValue(data.substring(index + 1, index + 3)) +
             data.substring(index + 3);
      index = data.indexOf('%', index + 1);   // replace next
    }
    System.out.println("final data: '" + data + "'");
    return data;
  }

// https://docs.oracle.com/javase/8/docs/api/java/io/ObjectOutputStream.html
  private synchronized void saveState() {
    System.out.println("calling saveState");
    try {
      java.io.FileOutputStream fos =
         new java.io.FileOutputStream(stateFileName);
      java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(fos);
      oos.writeObject(currentUrl);
      oos.writeObject(currentHtml);
      oos.writeObject(requestedHttp);
      oos.writeObject(requestedHttps);
      oos.writeObject(dns);
      oos.writeObject(cachedUrls);
      oos.close();
    } catch (Exception e) {
      System.out.println("exception " + e + " saving state");
      e.printStackTrace();
      System.exit(0);
    }
  }
// https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html
  @SuppressWarnings("unchecked")
  private synchronized void readState() {
    try {
      java.io.FileInputStream fis = new java.io.FileInputStream(stateFileName);
      java.io.ObjectInputStream ois = new java.io.ObjectInputStream(fis);
      currentUrl = (String) ois.readObject();
      currentHtml = (String) ois.readObject();
      requestedHttp = (java.util.Set<String>) ois.readObject();
      requestedHttps = (java.util.Map<Nonce, HttpsRequest>) ois.readObject();
      dns = (java.util.Map<String, java.net.InetAddress>) ois.readObject();
      cachedUrls = (java.util.List<String>) ois.readObject();
      ois.close();
    } catch (java.io.FileNotFoundException e) {
      System.out.println("state file not found, initializing to empty");
/*
    // https://stackoverflow.com/questions/4871051/how-to-get-the-current-working-directory-in-java
      currentUrl = "file://" + System.getProperty("user.dir") + "/index.html";
      try {
        currentHtml = java.nio.file.Files.readString(
                         java.nio.file.Path.of("index.html"));
      } catch (Exception indexExn) {
        System.out.println("exception " + indexExn + " reading index.html");
        currentHtml = "<h1>index.html not found!</h1>";
      }
*/
      currentUrl = "";
      currentHtml = makeContent(welcomeHtml, "");
      requestedHttp.clear();
      requestedHttps.clear();
      dns.clear();
      cachedUrls.clear();
      saveState();
    } catch (Exception e) {
      System.out.println("exception " + e + " reading state");
      e.printStackTrace();
    }
  }

  private String removeHTTPResponseHeader(String original) {
    if ((original.length() > 4) &&
        (original.substring(0,4).equalsIgnoreCase("HTTP"))) {
      int indexOfHeaderEnd = original.indexOf("\r\n\r\n");
      if (indexOfHeaderEnd != -1) {
        System.out.println("eliminating header " +
                           original.substring(0, indexOfHeaderEnd));
        return original.substring(indexOfHeaderEnd + 4);
      }
    }
    System.out.println("no header to eliminate");
    return original;
  }

  private String makeContent(String original, String url) {
    original = removeHTTPResponseHeader(original);
    String before = original;
    String after = "";
    int indexOfBodyEnd = original.indexOf("</body>");
    int indexOfHtmlEnd = original.indexOf("</html>");
    if (indexOfBodyEnd != -1) {
      before = original.substring(0, indexOfBodyEnd);
      after = original.substring(indexOfBodyEnd);
    } else if (indexOfHtmlEnd != -1) {
      before = original.substring(0, indexOfHtmlEnd);
      after = original.substring(indexOfHtmlEnd);
    }
    StringBuffer state = new StringBuffer(urlForm);
    if (! url.equals("")) {
      state.append("<p><p>This page is from <a href=\"" + url +
                   "\">" + url + "</a>\n");
    }
    if ((backUrl != null) && (backUrl.length() > 0) &&
        (! url.equalsIgnoreCase(backUrl))) {
      System.out.println("backUrl is '" + backUrl + "'");
      state.append("<br>\n<a href=\"" + backUrl +
                   "\">back to " + backUrl + "</a>\n");
    }
    // to do: add refresh and delete buttons for each line
    if (cachedUrls.size() > 0) {
      state.append("\n<p><b>Cached pages:</b>\n<ul>\n");
      for (String u: cachedUrls) {
        state.append("\n<li> <a href=\"" + u + "\">" + u + "</a>\n");
      }
      state.append("\n</ul>\n");
    }
    if ((requestedHttp.size() > 0) || (requestedHttps.size() > 0)) {
      state.append("\n<p><b>Requested:</b>\n<ul>\n");
      for (Nonce nonce: requestedHttps.keySet()) {
        HttpsRequest req = requestedHttps.get(nonce);
        state.append("\n<li> <a href=\"" + req.url + "\">" + req.url +
                     "</a>, nonce " + nonce + "\n");
      }
      for (String s: requestedHttp) {
        state.append("\n<li> <a href=\"" + s + "\">" + s + "</a>\n");
      }
      state.append("\n</ul>\n");
    }
    String result = before + state + futureWork + after;
    return result;
  }

  public boolean writeFile(String fname, byte[] contents) {
    java.io.File out = new java.io.File(fname);
    try (java.io.FileOutputStream stream =
          new java.io.FileOutputStream(out)) {
      stream.write(contents);
    } catch (java.io.IOException e) {
      System.out.println("error writing " + fname + ": " + e);
      return false;
    }
    return true;
  }

  static private String homePage()
  {
    // https://stackoverflow.com/questions/4871051/how-to-get-the-current-working-directory-in-java
    String currentDir = System.getProperty("user.dir");
    // System.out.println ("current directory " + currentDir);
    return "file://" + currentDir;
  }

/*
  // 2026/05/25: not currently used
  private Process startMkhtml ()
  {
    try {
      Process p = null;
      while (true) {
        ProcessBuilder pb = new ProcessBuilder ("./mkhtml", "" + port);
        pb.redirectOutput (ProcessBuilder.Redirect.INHERIT);
        pb.redirectError (ProcessBuilder.Redirect.INHERIT);
        p = pb.start ();
        try { Thread.sleep (100); } catch (Exception e) { };
        // exitValue should throw an exception if the process has NOT exited
        try {
          int n = p.exitValue ();
          System.out.println ("error " + n + " connecting to port " + port);
          port++;
        } catch (Exception e) {
          break; // process has not exited, success, end the loop
        };
      }
      System.out.println ("started process " + p + " on port " + port);
      return p;
    } catch (Exception e) {
      System.out.println ("xx got exception " + e);
    }
    return null;
  }
*/

  static String hexDigit(int i) {
    if (i < 10) return "" + i;
    if (i == 10) return "A";
    if (i == 11) return "B";
    if (i == 12) return "C";
    if (i == 13) return "D";
    if (i == 14) return "E";
    if (i == 15) return "F";
    return "X" + i;
  }
  static String hexByte(byte b) {
    int pos = (b + 256) % 256;
    int high = pos / 16;
    int low = pos % 16;
    return hexDigit(high) + hexDigit(low);
  }
  static String bytesToString(byte[] bytes) {
    String result = "";
    String separator = "";
    for (int i = 0; i < bytes.length; i++) {
      result += separator + hexByte(bytes[i]);
      separator = ",";
    }
    return result;
  }
  static void printBytes(byte[] bytes, String desc) {
    System.out.println("bytes of " + desc + " are [" +
                       bytesToString(bytes) + "]");
  }

  public java.net.DatagramSocket dgramSocket() {
    try {
      java.net.DatagramSocket sock = new java.net.DatagramSocket();
      // sock.setSoTimeout(100);   // short timeout so we read frequently
      Handler handler = new Handler(sock);
      System.out.println("calling handler.start");
      handler.start();
      System.out.println("done calling handler.start");
      return sock;
    } catch (java.net.SocketException e) {
      System.out.println("unable to create UDP socket");
      return null;
    }
  }

  // the session key must have 256 bits, i.e. 32 bytes
  // the pubkey is the server's public key
  public byte[] secureRequest(java.net.URL url, Nonce nonce,
                              byte[] sessionkey,
                              java.security.PublicKey pubkey) {
    final String nl = "\r\n";    // a standard newline as used on the web
    final String eos = "\0";     // separator
    assert(sessionkey.length == sessionKeySize);
    java.math.BigInteger sessionkeyBI = new java.math.BigInteger(1, sessionkey);
    String sessionkeyString =
       String.format("%0" + (sessionkey.length << 1) + "x", sessionkeyBI);
printBytes(sessionkey, "session key encoding " + sessionkeyString);
    String plaintext = "GET " + url.getPath() + " HTTP/1.1" + nl +
                       "Host: " + url.getHost() + nl +
                       "Nonce: " + nonce.toString() + nl +
                       "SessionKey: " + sessionkeyString + nl + nl;
    System.out.println("request to encrypt: " + plaintext);
    try {
      javax.crypto.Cipher c =
          javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
      // using CPT as the secure (CryPT) equivalenty to GET
      // include the host name to indicate whose key can decrypt
      String unencrypted = "CPT " + url.getHost() + nl;
      int ulen = unencrypted.length();
      c.init(javax.crypto.Cipher.ENCRYPT_MODE, pubkey);
      byte[] encrypted = c.doFinal(plaintext.getBytes());
      System.out.println("length of encrypted data is " + encrypted.length);
      byte[] result = new byte[encrypted.length + ulen];
      System.arraycopy(unencrypted.getBytes(), 0, result, 0, ulen);
      System.arraycopy(encrypted, 0, result, ulen, encrypted.length);
      return result;
    } catch (Exception e) {
      System.out.println("encryption throws exception " + e);
    }
    return null;
  }

  public String httpRequest(java.net.URL url) {
    final String nl = "\r\n";    // a standard newline as used on the web
    return "GET " + url.getPath() + " HTTP/1.1" + nl +
           "Host: " + url.getHost() + nl + nl;
  }

  // if successful, return values are in currentUrl and currentHtml
  private boolean readCachedFile(String fname) {
    try {
      java.nio.file.Path path = java.nio.file.Paths.get(fname);
      String contentStr = java.nio.file.Files.readString(path);
      String cachedUrl = homePage() + "/" + path.toString();
      currentHtml = makeContent(contentStr, cachedUrl);
      currentUrl = homePage() + "/" + path.toString();
System.out.println("request for " + currentUrl + " satisfied from cache");
      return true;
    } catch (java.io.IOException e) {
      System.out.println("unable to open cached file " + fname);
    }
    return false;
  }

  private class ResolveDNSThread extends java.lang.Thread {
    String host;
    public ResolveDNSThread (String name) {
      host = name;
    }
    public void run() {
      try {
        java.net.InetAddress result = java.net.InetAddress.getByName(host);
        System.out.println("thread: " + host + " -> " + result);
        saveDNS(host, result);
      } catch (java.net.UnknownHostException e) {
        System.out.println("background resolution: unknown host " + host);
      }
    }
  } 
  synchronized void saveDNS(String host, java.net.InetAddress result) {
    if (result != null) {
      dns.put(host, result);
      saveState();
    }
  }
  private java.net.InetAddress getIP(String host) {
    // first look up to see if we have cached the DNSs
    java.net.InetAddress result = dns.get(host);
    if (result != null) {
      System.out.println("found in cache: " + host + " -> " + result);
      // start a DNS resolution anyway, just in case the IP has changed
      ResolveDNSThread t = new ResolveDNSThread(host);
      t.start();          // may update result
      return result;
    }
    try {
      result = java.net.InetAddress.getByName(host);  // could be slow
      saveDNS(host, result);
      System.out.println("requested: " + host + " -> " + result);
    } catch (java.net.UnknownHostException e) {
      System.out.println("unknown host " + host);
    }
    return result;
  }
  private int getPort(java.net.URL url) {
    int result = url.getPort();
    if (result == -1) {
      result = asyncWebPort;
    }
    return result;
  }

  private void sendRequest(java.net.URL url, Nonce nonce,
                           java.security.PublicKey pubkey, byte[] sessionkey,
                           java.net.DatagramSocket sock) {
printBytes(sessionkey, "sendRequest sessionkey");
    String host = url.getHost();
    java.net.InetAddress IP = getIP(host);
    if (IP == null) {   // unable to resolve
System.out.println("unable to resolve IP for " + host);
      return;
    }
    int port = getPort(url);
    byte[] content = null;
    if (pubkey == null) {   // unencrypted
      content = httpRequest(url).getBytes();
    } else {               // pubkey != null, encrypt
      content = secureRequest(url, nonce, sessionkey, pubkey);
      if (content == null) {
        System.out.println("unable to create secure request for " + url);
        return;
      }
    }
//  printBytes(content, "request");
    java.net.DatagramPacket request =
      new java.net.DatagramPacket(content, content.length, IP, port);
    if (! addRemoveRequest(addRemove.add, url.toString(), nonce, sessionkey)) {
      // this is ok, continue
      // System.out.println("duplicate request " + url);
      // System.out.println("http requests are " + requestedHttp);
      // System.out.println("https requests are " + requestedHttps);
    }
    saveState();
    try {   // if it is a duplicate request, resend it anyway
      sock.send(request);
    } catch (java.io.IOException e) {
      System.out.println("unable to send UDP to " + IP + "/" + port);
    }
  }

  public void requestUrl(java.net.URL url, java.net.DatagramSocket sock) {
    String urlString = url.toString();
    if (url.getPath().length() == 0) {
      try {
        java.net.URI uri = new java.net.URI(urlString + "/");
        url = uri.toURL();
      } catch (java.net.URISyntaxException exn) {
        System.out.println("requestUrl error: ignoring uri " + url);
      } catch (java.net.MalformedURLException exn) {
        System.out.println("requestUrl error: ignoring url " + url);
      }
      urlString = url.toString();
    }
    String sanitized = urlString.replaceAll("[^\\w]+", "_");
    // turn https_www_example_com into https/www_example_com
    String fname = sanitized.replaceFirst("[_]", "/");
    if (readCachedFile (fname)) {
      return;
    }
    if (readCachedFile (fname.replaceFirst("[_]", "_" + asyncWebPort + "_"))) {
      return;
    }
    boolean secure = (url.getProtocol().equals("https"));
    Nonce nonce = null;
    byte[] sessionkey = new byte[sessionKeySize];
    String host = url.getHost();
    java.security.PublicKey pubkey = null;
    if (secure) {
      boolean found = false;
      for (Nonce searchNonce: requestedHttps.keySet()) {
        HttpsRequest req = requestedHttps.get(searchNonce);
        if (req.url.equalsIgnoreCase(urlString)) {
          nonce = searchNonce;
          System.arraycopy(req.sessionkey, 0, sessionkey, 0, sessionKeySize); 
          found = true;
        }
      }
      if (! found) {
        nonce = new Nonce();      // session key filled out by addRemove
      }
      // check if we already have a certificate
      pubkey = Handler.getPubKey(host);
      if (pubkey == null) {  // request the certificate
        System.out.println("no pubkey for " + host + ", requesting");
        String content = "CRT " + host + "\r\n\r\n" ;
        byte[] cBytes = content.getBytes();
        java.net.InetAddress IP = getIP(host);
        if (IP == null) {   // unable to resolve
System.out.println("unable to resolve IP for " + host);
          return;
        }
        java.net.DatagramPacket request =
          new java.net.DatagramPacket(cBytes, cBytes.length, IP, getPort(url));
        // record the request and fill in sessionkey (which is not used here).
        // It's ok if it is not a new request
        addRemoveRequest(addRemove.add, urlString, nonce, sessionkey);
        saveState();
        System.out.println("calling sock.send");
        try {
          sock.send(request);   // request the certificate
        } catch (java.io.IOException e) {
          System.out.println("unable to send certificate request to " + host);
        }
        System.out.println("finished sending certificate request to " + host);
        return;               // nothing else we can do without the cert
      } else {  // have certificate, continue with requesting the https page
        // record the request and fill in sessionkey
        // It's ok if it is not a new request
        addRemoveRequest(addRemove.add, urlString, nonce, sessionkey);
        saveState();
      }
    }
    // finally, can send the request
    printBytes(sessionkey, "requestUrl sessionkey");
    sendRequest(url, nonce, pubkey, sessionkey, sock);
  }

  public ABrowser (String fname)
  {
    // int URLport = 80;
    // subProcess = startMkhtml ();
    System.out.println("reading state");
    readState();
    System.out.println("done reading state, current URL " + currentUrl);
    java.net.DatagramSocket sock = dgramSocket();
    java.awt.Component component = null;
    try
    {
/*
System.out.println("creating JEditorPane(" + homePage() + "/" + fname + ")");
      page = new javax.swing.JEditorPane (homePage() + "/" + fname);
System.out.println("created JEditorPane(" + homePage() + "/" + fname + ")");
*/
      // page = new javax.swing.JEditorPane(currentUrl);
      page = new javax.swing.JEditorPane("text/html", currentHtml);
      page.setEditable (false);     // so can click on links
      // code suggested by duckduckgo ai, otherwise JEditorPane handles the form
      javax.swing.text.html.HTMLEditorKit kit =
        (javax.swing.text.html.HTMLEditorKit)
           page.getEditorKitForContentType("text/html");
      kit.setAutoFormSubmission(false);
      // end code suggested by duckduckgo ai
      page.addHyperlinkListener (new javax.swing.event.HyperlinkListener() {
// from https://docs.oracle.com/javase/7/docs/api/javax/swing/JEditorPane.html
        public void hyperlinkUpdate (javax.swing.event.HyperlinkEvent e) {
          // System.out.println("event action: page " + page + ", event " + e);
          if (e.getEventType () ==
              javax.swing.event.HyperlinkEvent.EventType.ACTIVATED) {
            System.out.println("clicked URL " + e.getURL ());
            if (e instanceof javax.swing.text.html.FormSubmitEvent form) {
              // parse data, of the form "protocol=https&url=example.org"
              String data = form.getData();
              final String pMarker = "protocol=";
              final String uMarker = "url=";
              int beginUrl = data.indexOf(uMarker);
              if (beginUrl != -1) {
                String urlS = data.substring(beginUrl + uMarker.length());
                urlS = sanitizeFormData(urlS);
                int beginProtocol = data.indexOf(pMarker);
                int sep = data.indexOf("&");
                if ((beginProtocol != -1) && (sep != -1)) {
                  urlS = data.substring(beginProtocol + pMarker.length(), sep) +
                         "://" + urlS;
                } else if (beginProtocol != -1) {
                  urlS = data.substring(beginProtocol + pMarker.length()) +
                         "://" + urlS;
                } else {     // something wrong with the html
                  System.out.println("broken form input: " + data);
                  urlS = "https://" + urlS;   // https is the default
                }
                System.out.println("loading URL " + urlS);
                java.net.URI uri = null;
                java.net.URL url = null;
                try {
                  uri = new java.net.URI(urlS);
                  url = uri.toURL();
                  requestUrl(url, sock);
                } catch (java.net.URISyntaxException exn) {
                  System.out.println("error: bad user url '" + urlS + "'");
                } catch (java.net.MalformedURLException exn) {
                  System.out.println("error: ignoring user url " + urlS);
                }
              } else {
                System.out.println("error: method " + form.getMethod() +
                                   ", data " + form.getData() +
                                   ", target " + form.getTarget());
              }
              return;
            }
            javax.swing.JEditorPane sourcePane =
              (javax.swing.JEditorPane) e.getSource();
            // for now ignore HTMLFrameHyperlinkEvent, see above link to handle
            try {
              System.out.println("URL protocol = " + e.getURL().getProtocol());
              System.out.println("URL path     = " + e.getURL().getPath());
              if (! e.getURL().getFile().equals(e.getURL().getPath()))
                System.out.println("URL filename = " + e.getURL().getFile());
              if (e.getURL().getProtocol().equals("file")) {
                String url = e.getURL().toString();
                String fname = url.substring(5);
                // eliminate all but the last leading /
                while ((fname.length() > 1) &&
                       (fname.substring(0,2).equals("//"))) {
                  fname = fname.substring(1);
                }
                try {
                  System.out.println("path is " + fname);
                  java.nio.file.Path path = java.nio.file.Paths.get(fname);
                  String content = java.nio.file.Files.readString(path);
                  currentUrl = "file://" + fname;
                  System.out.println("set currentUrl to " + currentUrl);
                  currentHtml = makeContent(new String(content), url);
                  sourcePane.setPage (e.getURL ());
                  update();
                } catch (java.nio.file.NoSuchFileException exn) {
                  System.out.println("file " + fname + " not found");
                }
//              page.setPage (e.getURL ());
              } else {
                if (! e.getURL().getAuthority().equals(e.getURL().getHost()))
                  System.out.println("URL auth = " + e.getURL().getAuthority());
                System.out.println("URL host  = " + e.getURL().getHost());
                if (e.getURL().getPort() != -1) {
                  System.out.println("URL port  = " + e.getURL().getPort());
                }
                if (e.getURL().getQuery() != null)
                  System.out.println("URL query = " + e.getURL().getQuery());
                if (e.getURL().getRef() != null)
                  System.out.println("URL ref   = " + e.getURL().getRef());
                System.out.println("requested external URL " + e.getURL());
                requestUrl(e.getURL(), sock);
              }
            } catch (Exception exn) {
              System.out.println ("xy got exception " + exn +
                                  " loading url " + e.getURL ());
              exn.printStackTrace();
            }
          } // ends eventType == ACTIVATED
        }   // ends hyperlinkUpdate
      });   // ends the anonymous inner class
      component = page;
    } catch (Exception e) {
      System.out.println ("xz got exception " + e + " requesting " + fname);
      component = new javax.swing.JLabel (fname + ": error " + e);
      System.exit (1);
    }
    scroll = new javax.swing.JScrollPane (component);
    setDefaultCloseOperation (EXIT_ON_CLOSE);
    add (scroll);
    // pack ();	// reset the size to match the contents - alternative to setSize
    setSize (1500, 1000);
    setVisible (true);
  }

  // this instance variable is only used by update, so declared here
  String oldHtml = "";
  public void update ()
  {
    boolean unchanged = true;
    java.awt.Component component = null;
    try {
      if (! currentHtml.equals(oldHtml)) {
        // System.out.println("changing html");
        oldHtml = currentHtml;
        unchanged = false;
      }
      if (! currentUrl.equals(backUrl)) {
        System.out.println("changing file path from " + backUrl +
                           " to " + currentUrl);
        backUrl = currentUrl;
        unchanged = false;
      }
      if (unchanged) {
        return;
      }
      remove (scroll);
      // page.setPage(currentUrl);
      page.setText(currentHtml);
      // https://docs.oracle.com/en/java/javase/17/docs/api/java.desktop/javax/swing/JEditorPane.html#setPage(java.lang.String)
      // System.out.println("about to call getDocument");
      javax.swing.text.Document d = page.getDocument();
      // System.out.println("done calling getDocument");
      d.putProperty(javax.swing.text.Document.StreamDescriptionProperty, null);
      // System.out.println("done calling putProperty");
      component = page;
    } catch (Exception e) {
      System.out.println ("update got exception " + e);
      component = new javax.swing.JLabel (currentUrl + ": error " + e);
    }
    scroll = new javax.swing.JScrollPane (component);
    // System.out.println("done creating JScrollPane");
    setDefaultCloseOperation (EXIT_ON_CLOSE);
    add (scroll);
    // System.out.println("done adding scroll");
    // pack ();	// reset the size to match the contents – no need for setSize
    try {
      setVisible (true);
    } catch (java.lang.ArrayIndexOutOfBoundsException e) {
      try {
        Thread.sleep(1000);
      } catch (java.lang.InterruptedException exn) {
        System.out.println("sleep was interrupted");
      }
      System.out.println("setVisible threw exception, trying again");
      setVisible (true);
    }
    // System.out.println("done setting visible");
  }

  public static void main (String[]args)
  {
    String file = "index.html";
    if (args.length > 0) {
      file = args[0];
    }
    ABrowser myPage = new ABrowser(file);
    while (true) {
      try { Thread.sleep (100); } catch (Exception e) { };
      // System.out.println ("updating page " + myPage.currentUrl);
      myPage.update ();
    }
  }

}

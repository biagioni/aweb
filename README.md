# AWeb
Research prototype demonstrating the 2026 Asynchronous Web protocol

The web can be browsed asynchronously if:

- there is at least a low-bandwidth connection for requests

- there is a connection back for responses

Both of these connections can be shared, e.g. using SMS or an Aloha-style protocol for requests and a broadcast (perhaps FM -- see also [1]) connection for responses.

This code is an initial prototype implementation of such an Asynchronous Web access protocol, which we call AWeb.  The basic principle is to cache everything possible to minimize the number of round-trips needed to obtain content (see Footnote 1).  Similar to the Quic protocol, AWeb uses UDP instead of TCP to remove one further round-trip needed for the TCP 3-way handshake. 

To maintain https-equivalent security, a secure request is encrypted using the server's public key.  The encrypted part of the request includes a nonce (use-once random number) and a random session key used to encrypt the response.  The nonce is sent in the clear with the encrypted response, so clients listening to a broadcast channel can tell which responses to decrypt.

The specific code includes a stand-alone browser and server.  Wider adoption would be achieved by implementing the protocol as part of popular browsers and servers, e.g. the open source Chromium Browser and Apache web server.

The client/browser is implemented in Java, and found in the file ABrowser.java.  The client persists long-term state, including IP addresses obtained via DNS resolutions, in a file called aweb.state.  Host certificates are saved in subdirectory certs.  Cached web pages are saved in subdirectories http (for pages downloaded without encryption) and https.

The server is implemented in Python3 and found in the file aweb-server.py.  The server can be started as root, in which case it becomes the user 'nobody' after reading all the private keys found in the subdirectory keys.  The certificates (public keys) in the subdirectory certs are read as requested rather than at startup time.

# References and footnotes:

[1] Ayush Pandey, Rohail Asim, Jean Louis K. E. Fendji, Talal Rahwan, Matteo Varvello, Yasir Zaki, "SONIC: Cost-Effective Web Access for Developing Countries" arXiv:2505.16519v1, 22 May 2025

Footnote 1: caching as much as possible is in contrast to current philosophy, which always tries to obtain the most current version of information such as DNS resolution IP addresses and web certificates/public keys as well as actual web content.

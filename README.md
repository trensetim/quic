# quic
Pure Java implementation of IETF [QUIC](https://quicwg.github.io/).
The primary goal of this project is to eventually evolve to Java's standard implementation of QUIC Protocol.

## Project Structure
This project combines a clean QUIC interface in com.timtrense.quic as well as a default implementation for it in com.timtrense.quic.impl.base and ~.frames and ~.packets.
Because QUIC needs to have a specific variant of TLS 1.3 implemented to work, the com.timtrense.quic.tls package
 addresses an implementation of TLS which is specific for QUIC. 

## Project Status
The implementation of the QUIC protocol was standardised in RFC 9000 and implement the IETF specification at https://tools.ietf.org/html/draft-ietf-quic-transport-32 and referenced documents.
I will set up  a Dockerfile for integration testing at https://quicwg.org/ as soon as this implementation reaches usability.

## QUIC Protocol Features

QUIC has many benefits when compared with existing "TLS over TCP" scenarios:

- All packets are encrypted and handshake is authenticated with TLS 1.3.
- Parallel streams of both reliable and unreliable application data.
- Exchange application data in the first round trip (0-RTT).
- Improved congestion control and loss recovery.
- Survives a change in the clients IP address or port.
- Stateless load balancing.
- Easily extendable for new features and extensions.
- QUIC conforming with [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)
- HTTP/3 conforming with [RFC9114](https://datatracker.ietf.org/doc/html/rfc9114)
- Minimal TLS 1.3 implementation conforming with [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446)

## Contributing
Contributions welcome. Please feel free to contact me or write a pull request.
Because the main focus currently is implementing the protocol itself, there are many test cases yet to write. 
Or sonarqube issues to fix. You may have a look on the sonarqube or test cases as a starting point.
I would really appreciate any help I could possibly get with this project.

## License
This project is open source and freely available even for commercial use and in undisclosed commercial projects.

## Acknowledgements
Thanks to ptrd/kwik for doing the heavy lifting on most parts of implementing the QUIC protocol 
and related TLS implementation (I would really like him to open source it). 
I decided to do my own implementation of QUIC because I felt too much of a pain in trying to understand kwiks source
 code and doubting that that code base can be long-term maintained.
 
This implementation uses [HKDF by Patrick Favre-Bulle](https://github.com/patrickfav/hkdf)
 because it is nicely split into extract and expand, which is necessary for how TLS works in QUIC.
And it also uses [Bytes by Patrick Favre-Bulle](https://github.com/patrickfav/bytes-java)
 because with it, by-quic-defined byte arrays are made immutable.
 
And huge thanks to https://github.com/quicwg for making that promising protocol in the first place.

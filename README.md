# quic
Pure Java implementation of QUIC.
The primary goal of this project is to eventually evolve to Java's standard implementation of QUIC.

[![Coverage](https://sonarqube.timtrense.com/api/project_badges/measure?project=com.timtrense.quic&metric=coverage)](https://sonarqube.timtrense.com/dashboard?id=com.timtrense.quic)
[![Quality Gate Status](https://sonarqube.timtrense.com/api/project_badges/measure?project=com.timtrense.quic&metric=alert_status)](https://sonarqube.timtrense.com/dashboard?id=com.timtrense.quic)
[![Build Status](https://jenkins.timtrense.com/buildStatus/icon?job=com.timtrense.quic)](https://jenkins.timtrense.com/buildStatus/icon?job=com.timtrense.quic)

## Project Structure
This project combines a clean QUIC interface in com.timtrense.quic as well as a default implementation for it in com.timtrense.quic.impl.base and ~.frames and ~.packets.

## Project Status
The implementation of the protocol is still work in progess but aims to completly adhere and implement the IETF specification at https://tools.ietf.org/html/draft-ietf-quic-transport-32 and referenced documents.
I will set up  a Dockerfile for integration testing at https://quicwg.org/ as soon as this implementation reaches usability.

## Contributing
Contributions welcome. Please feel free to contact me or write a pull request.

## License
This project is open source and freely available even for commercial use and in undisclosed commercial projects.

## Acknowledgements
Huge thanks to ptrd/kwik for doing the heavy lifting on most parts of implementing the QUIC protocol. 
I decided to do my own implementation of QUIC because i felt too much of a pain of trying to understand kwiks source code and doubting that that code base can be long-term maintained.
The implementation uses [HKDF by Patrick Favre-Bulle](https://github.com/patrickfav/hkdf Github/patrickfav/hdkf)
 because it is nicely split into extract and expand which is necessary for how the TLS-implementation works.
 
And huge thanks to https://github.com/quicwg for making that promising protocol in the first place.

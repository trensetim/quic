package com.timtrense.quic.tls.handshake;

import com.timtrense.quic.tls.ExtendedHandshake;

/**
 * Common base class for messages from
 * <a href="https://tools.ietf.org/html/rfc8446#section-4.3">Section 4.3 "Server Parameters"</a>
 * of the TLS 1.3 Specification.
 *
 * <p/>
 * The next two messages from the server, EncryptedExtensions and
 * CertificateRequest, contain information from the server that
 * determines the rest of the handshake.  These messages are encrypted
 * with keys derived from the server_handshake_traffic_secret.
 *
 * @author Tim Trense
 */
public abstract class ServerParametersMessage extends ExtendedHandshake {
}

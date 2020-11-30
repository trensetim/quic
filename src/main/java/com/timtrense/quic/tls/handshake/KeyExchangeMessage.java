package com.timtrense.quic.tls.handshake;

import com.timtrense.quic.tls.ExtendedHandshake;

/**
 * Common base class for messages from
 * <a href="https://tools.ietf.org/html/rfc8446#section-4.1">Section 4.1 "Key Exchange Messages"</a>
 * of the TLS 1.3 Specification.
 *
 * <p/>
 * The key exchange messages are used to determine the security
 * capabilities of the client and the server and to establish shared
 * secrets, including the traffic keys used to protect the rest of the
 * handshake and the data.
 *
 * @author Tim Trense
 */
public abstract class KeyExchangeMessage extends ExtendedHandshake {
}

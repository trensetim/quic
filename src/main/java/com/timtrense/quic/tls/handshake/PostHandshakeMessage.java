package com.timtrense.quic.tls.handshake;

import com.timtrense.quic.tls.Handshake;

/**
 * Common base class for messages from
 * <a href="https://tools.ietf.org/html/rfc8446#section-4.6">Section 4.6 "Post-Handshake Messages"</a>
 * of the TLS 1.3 Specification.
 *
 * <p/>
 * TLS also allows other messages to be sent after the main handshake.
 * These messages use a handshake content type and are encrypted under
 * the appropriate application traffic key.
 * <p/>
 *
 * Implementation Note: Because the term "Handshake" describes a message in the protocol,
 * this class extends {@link Handshake}. Confusingly Handshake means "message" here.
 *
 * @author Tim Trense
 */
public abstract class PostHandshakeMessage extends Handshake {
}

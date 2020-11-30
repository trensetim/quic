package com.timtrense.quic.tls.handshake;

import com.timtrense.quic.tls.ExtendedHandshake;
import com.timtrense.quic.tls.HandshakeType;

/**
 * In all handshakes, the server MUST send the EncryptedExtensions
 * message immediately after the ServerHello message.  This is the first
 * message that is encrypted under keys derived from the
 * server_handshake_traffic_secret.
 * <p/>
 * The EncryptedExtensions message contains extensions that can be
 * protected, i.e., any which are not needed to establish the
 * cryptographic context but which are not associated with individual
 * certificates.  The client MUST check EncryptedExtensions for the
 * presence of any forbidden extensions and if any are found MUST abort
 * the handshake with an "illegal_parameter" alert.
 * <p/>
 * <b>Note: This message contains information that determines the rest
 * of the handshake, but is encrypted with keys derived from the
 * server_handshake_traffic_secret</b>. See
 * <a href="https://tools.ietf.org/html/rfc8446#section-4.3">TLS 1.3 Spec/Section 4.3</a>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.3.1">TLS 1.3 Spec/Section 4.3.1</a>
 */
public class EncryptedExtensions extends ExtendedHandshake {
    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.ENCRYPTED_EXTENSIONS;
    }
}

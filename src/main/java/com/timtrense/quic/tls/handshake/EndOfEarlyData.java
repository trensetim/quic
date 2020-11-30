package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Handshake;
import com.timtrense.quic.tls.HandshakeType;

/**
 * <pre>
 *     struct {} EndOfEarlyData;
 * </pre>
 * If the server sent an "early_data" extension in EncryptedExtensions,
 * the client MUST send an EndOfEarlyData message after receiving the
 * server Finished.  If the server does not send an "early_data"
 * extension in EncryptedExtensions, then the client MUST NOT send an
 * EndOfEarlyData message.  This message indicates that all 0-RTT
 * application_data messages, if any, have been transmitted and that the
 * following records are protected under handshake traffic keys.
 * Servers MUST NOT send this message, and clients receiving it MUST
 * terminate the connection with an "unexpected_message" alert.  This
 * message is encrypted under keys derived from the
 * client_early_traffic_secret.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.4">TLS 1.3 Spec/Section 4.4.4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class EndOfEarlyData extends Handshake {

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.END_OF_EARLY_DATA;
    }
}

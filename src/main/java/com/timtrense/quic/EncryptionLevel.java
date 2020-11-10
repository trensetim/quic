package com.timtrense.quic;

/**
 * Data is protected using a number of encryption levels.
 *
 * Application Data may appear only in the Early Data and Application
 * Data levels.  Handshake and Alert messages may appear in any level.
 *
 * The 0-RTT handshake is only possible if the client and server have
 * previously communicated.  In the 1-RTT handshake, the client is
 * unable to send protected Application Data until it has received all
 * of the Handshake messages sent by the server.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-2.1">QUIC Spec-TLS/Section 2.1</a>
 */
public enum EncryptionLevel {

    /**
     * Initial Keys
     */
    INITIAL,
    /**
     * Early Data (0-RTT) Keys
     */
    EARLY_DATA,
    /**
     * Handshake Keys
     */
    HANDSHAKE,
    /**
     * Application Data (1-RTT) Keys
     */
    APPLICATION_DATA
}

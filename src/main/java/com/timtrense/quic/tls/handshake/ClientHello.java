package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.CipherSuite;
import com.timtrense.quic.tls.HandshakeType;

/**
 * When a client first connects to a server, it is REQUIRED to send the
 * ClientHello as its first TLS message.  The client will also send a
 * ClientHello when the server has responded to its ClientHello with a
 * HelloRetryRequest.  In that case, the client MUST send the same
 * ClientHello without modification, except as follows:
 * <ul>
 *     <li>
 *         If a "key_share" extension was supplied in the HelloRetryRequest,
 *         replacing the list of shares with a list containing a single
 *         KeyShareEntry from the indicated group.
 *     </li>
 *     <li>
 *         Removing the "early_data" extension (Section 4.2.10) if one was
 *         present.  Early data is not permitted after a HelloRetryRequest.
 *     </li>
 *     <li>
 *         Including a "cookie" extension if one was provided in the
 *         HelloRetryRequest.
 *     </li>
 *     <li>
 *         Updating the "pre_shared_key" extension if present by recomputing
 *         the "obfuscated_ticket_age" and binder values and (optionally)
 *         removing any PSKs which are incompatible with the server's
 *         indicated cipher suite.
 *     </li>
 *     <li>
 *         Optionally adding, removing, or changing the length of the
 *         "padding" extension [RFC7685].
 *     </li>
 *     <li>
 *         Other modifications that may be allowed by an extension defined in
 *         the future and present in the HelloRetryRequest.
 *     </li>
 * </ul>
 * Because TLS 1.3 forbids renegotiation, if a server has negotiated
 * TLS 1.3 and receives a ClientHello at any other time, it MUST
 * terminate the connection with an "unexpected_message" alert.
 * <p/>
 * If a server established a TLS connection with a previous version of
 * TLS and receives a TLS 1.3 ClientHello in a renegotiation, it MUST
 * retain the previous protocol version.  In particular, it MUST NOT
 * negotiate TLS 1.3.
 * <p/>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.1.2">TLS 1.3 Spec/Section 4.1.2</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ClientHello extends KeyExchangeMessage {

    /*
    legacy_version:  In previous versions of TLS, this field was used for
      version negotiation and represented the highest version number
      supported by the client.  Experience has shown that many servers
      do not properly implement version negotiation, leading to "version
      intolerance" in which the server rejects an otherwise acceptable
      ClientHello with a version number higher than it supports.  In
      TLS 1.3, the client indicates its version preferences in the
      "supported_versions" extension (Section 4.2.1) and the
      legacy_version field MUST be set to 0x0303, which is the version
      number for TLS 1.2.  TLS 1.3 ClientHellos are identified as having
      a legacy_version of 0x0303 and a supported_versions extension
      present with 0x0304 as the highest version indicated therein.
      (See Appendix D for details about backward compatibility.)
     */

    /**
     * random:  32 bytes generated by a secure random number generator.  See
     * Appendix C for additional information.
     */
    private byte[] random;

    /**
     * Versions of TLS before TLS 1.3 supported a
     * "session resumption" feature which has been merged with pre-shared
     * keys in this version (see Section 2.2).  A client which has a
     * cached session ID set by a pre-TLS 1.3 server SHOULD set this
     * field to that value.  In compatibility mode (see Appendix D.4),
     * this field MUST be non-empty, so a client not offering a
     * pre-TLS 1.3 session MUST generate a new 32-byte value.  This value
     * need not be random but SHOULD be unpredictable to avoid
     * implementations fixating on a specific value (also known as
     * ossification).  Otherwise, it MUST be set as a zero-length vector
     * (i.e., a zero-valued single byte length field).
     */
    private byte[] legacySessionId;

    /**
     * cipher_suites:  A list of the symmetric cipher options supported by
     * the client, specifically the record protection algorithm
     * (including secret key length) and a hash to be used with HKDF, in
     * descending order of client preference.  Values are defined in
     * Appendix B.4.  If the list contains cipher suites that the server
     * does not recognize, support, or wish to use, the server MUST
     * ignore those cipher suites and process the remaining ones as
     * usual.  If the client is attempting a PSK key establishment, it
     * SHOULD advertise at least one cipher suite indicating a Hash
     * associated with the PSK.
     * <p/>
     * <b>Length: 2..2^16-2 instances</b>
     */
    private CipherSuite[] cipherSuites;

    /**
     * Versions of TLS before 1.3 supported
     * compression with the list of supported compression methods being
     * sent in this field.  For every TLS 1.3 ClientHello, this vector
     * MUST contain exactly one byte, set to zero, which corresponds to
     * the "null" compression method in prior versions of TLS.  If a
     * TLS 1.3 ClientHello is received with any other value in this
     * field, the server MUST abort the handshake with an
     * "illegal_parameter" alert.  Note that TLS 1.3 servers might
     * receive TLS 1.2 or prior ClientHellos which contain other
     * compression methods and (if negotiating such a prior version) MUST
     * follow the procedures for the appropriate prior version of TLS.
     * <p/>
     * <b>Length: 1..2^8-1 bytes</b>
     */
    private byte[] legacyCompressionMethods;

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.CLIENT_HELLO;
    }
}

package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * The server will send this message in response to a ClientHello
 * message if it is able to find an acceptable set of parameters but the
 * ClientHello does not contain sufficient information to proceed with
 * the handshake.  As discussed in Section 4.1.3, the HelloRetryRequest
 * has the same format as a ServerHello message, and the legacy_version,
 * legacy_session_id_echo, cipher_suite, and legacy_compression_method
 * fields have the same meaning.  However, for convenience we discuss
 * "HelloRetryRequest" throughout this document as if it were a distinct
 * message.
 * <p/>
 * The server's extensions MUST contain "supported_versions".
 * Additionally, it SHOULD contain the minimal set of extensions
 * necessary for the client to generate a correct ClientHello pair.  As
 * with the ServerHello, a HelloRetryRequest MUST NOT contain any
 * extensions that were not first offered by the client in its
 * ClientHello, with the exception of optionally the "cookie" (see
 * Section 4.2.2) extension.
 * <p/>
 * Upon receipt of a HelloRetryRequest, the client MUST check the
 * legacy_version, legacy_session_id_echo, cipher_suite, and
 * legacy_compression_method as specified in Section 4.1.3 and then
 * process the extensions, starting with determining the version using
 * "supported_versions".  Clients MUST abort the handshake with an
 * "illegal_parameter" alert if the HelloRetryRequest would not result
 * in any change in the ClientHello.  If a client receives a second
 * HelloRetryRequest in the same connection (i.e., where the ClientHello
 * was itself in response to a HelloRetryRequest), it MUST abort the
 * handshake with an "unexpected_message" alert.
 * <p/>
 * Otherwise, the client MUST process all extensions in the
 * HelloRetryRequest and send a second updated ClientHello.  The
 * HelloRetryRequest extensions defined in this specification are:
 * <ul>
 *     <li>
 *         supported_versions (see Section 4.2.1)
 *     </li>
 *     <li>
 *         cookie (see Section 4.2.2)
 *     </li>
 *     <li>
 *         key_share (see Section 4.2.8)
 *     </li>
 * </ul>
 * A client which receives a cipher suite that was not offered MUST
 * abort the handshake.  Servers MUST ensure that they negotiate the
 * same cipher suite when receiving a conformant updated ClientHello (if
 * the server selects the cipher suite as the first step in the
 * negotiation, then this will happen automatically).  Upon receiving
 * the ServerHello, clients MUST check that the cipher suite supplied in
 * the ServerHello is the same as that in the HelloRetryRequest and
 * otherwise abort the handshake with an "illegal_parameter" alert.
 * <p/>
 * In addition, in its updated ClientHello, the client SHOULD NOT offer
 * any pre-shared keys associated with a hash other than that of the
 * selected cipher suite.  This allows the client to avoid having to
 * compute partial hash transcripts for multiple hashes in the second
 * ClientHello.
 * <p/>
 * The value of selected_version in the HelloRetryRequest
 * "supported_versions" extension MUST be retained in the ServerHello,
 * and a client MUST abort the handshake with an "illegal_parameter"
 * alert if the value changes.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.1.4">TLS 1.3 Spec/Section 4.1.4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class HelloRetryRequest extends ServerHello {

    /**
     * For reasons of backward compatibility with middleboxes (see
     * Appendix D.4), the HelloRetryRequest message uses the same structure
     * as the ServerHello, but with Random set to the special value of the
     * SHA-256 of "HelloRetryRequest":
     * <pre>
     *     CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
     *     C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
     * </pre>
     */
    public static final byte[] SPECIFIC_RANDOM = new byte[]{
            (byte)0xCF, (byte)0x21, (byte)0xAD, (byte)0x74, (byte)0xE5, (byte)0x9A, (byte)0x61, (byte)0x11,
            (byte)0xBE, (byte)0x1D, (byte)0x8C, (byte)0x02, (byte)0x1E, (byte)0x65, (byte)0xB8, (byte)0x91,
            (byte)0xC2, (byte)0xA2, (byte)0x11, (byte)0x16, (byte)0x7A, (byte)0xBB, (byte)0x8C, (byte)0x5E,
            (byte)0x07, (byte)0x9E, (byte)0x09, (byte)0xE2, (byte)0xC8, (byte)0xA8, (byte)0x33, (byte)0x9C
    };

    // {@link #getMessageType} will return {@link HandshakeType#SERVER_HELLO} as super does

}

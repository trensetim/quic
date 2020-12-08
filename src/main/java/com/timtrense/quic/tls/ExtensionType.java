package com.timtrense.quic.tls;

import lombok.Getter;

import com.timtrense.quic.tls.extensions.ApplicationLayerProtocolNegotiationExtension;
import com.timtrense.quic.tls.extensions.CertificateAuthoritiesExtension;
import com.timtrense.quic.tls.extensions.ClientSupportedVersionsExtension;
import com.timtrense.quic.tls.extensions.CookieExtension;
import com.timtrense.quic.tls.extensions.EarlyDataIndicationExtension;
import com.timtrense.quic.tls.extensions.KeyShareClientHelloExtension;
import com.timtrense.quic.tls.extensions.KeyShareExtensionBase;
import com.timtrense.quic.tls.extensions.KeyShareHelloRetryRequestExtension;
import com.timtrense.quic.tls.extensions.KeyShareServerHelloExtension;
import com.timtrense.quic.tls.extensions.OidFilterExtension;
import com.timtrense.quic.tls.extensions.PostHandshakeClientAuthExtension;
import com.timtrense.quic.tls.extensions.PreSharedKeyClientHelloExtension;
import com.timtrense.quic.tls.extensions.PreSharedKeyExtensionBase;
import com.timtrense.quic.tls.extensions.PreSharedKeyServerHelloExtension;
import com.timtrense.quic.tls.extensions.PskKeyExchangeModeExtension;
import com.timtrense.quic.tls.extensions.ServerNameIndicationExtension;
import com.timtrense.quic.tls.extensions.ServerSupportedVersionsExtension;
import com.timtrense.quic.tls.extensions.SignatureAlgorithmsExtension;
import com.timtrense.quic.tls.extensions.StatusRequestExtensionBase;
import com.timtrense.quic.tls.extensions.StatusRequestOcspExtension;
import com.timtrense.quic.tls.extensions.SupportedGroupsExtension;

/**
 * Extensions are generally structured in a request/response fashion,
 * though some extensions are just indications with no corresponding
 * response.  The client sends its extension requests in the ClientHello
 * message, and the server sends its extension responses in the
 * ServerHello, EncryptedExtensions, HelloRetryRequest, and Certificate
 * messages.  The server sends extension requests in the
 * CertificateRequest message which a client MAY respond to with a
 * Certificate message.  The server MAY also send unsolicited extensions
 * in the NewSessionTicket, though the client does not respond directly
 * to these.
 * <p/>
 * Implementations MUST NOT send extension responses if the remote
 * endpoint did not send the corresponding extension requests, with the
 * exception of the "cookie" extension in the HelloRetryRequest.  Upon
 * receiving such an extension, an endpoint MUST abort the handshake
 * with an "unsupported_extension" alert.
 * <p/>
 * The table below indicates the messages where a given extension may
 * appear, using the following notation: CH (ClientHello),
 * SH (ServerHello), EE (EncryptedExtensions), CT (Certificate),
 * CR (CertificateRequest), NST (NewSessionTicket), and
 * HRR (HelloRetryRequest).  If an implementation receives an extension
 * which it recognizes and which is not specified for the message in
 * which it appears, it MUST abort the handshake with an
 * "illegal_parameter" alert.
 * <p/>
 * <pre>
 *     +--------------------------------------------------+-------------+
 *    | Extension                                        |     TLS 1.3 |
 *    +--------------------------------------------------+-------------+
 *    | server_name [RFC6066]                            |      CH, EE |
 *    |                                                  |             |
 *    | max_fragment_length [RFC6066]                    |      CH, EE |
 *    |                                                  |             |
 *    | status_request [RFC6066]                         |  CH, CR, CT |
 *    |                                                  |             |
 *    | supported_groups [RFC7919]                       |      CH, EE |
 *    |                                                  |             |
 *    | signature_algorithms (RFC 8446)                  |      CH, CR |
 *    |                                                  |             |
 *    | use_srtp [RFC5764]                               |      CH, EE |
 *    |                                                  |             |
 *    | heartbeat [RFC6520]                              |      CH, EE |
 *    |                                                  |             |
 *    | application_layer_protocol_negotiation [RFC7301] |      CH, EE |
 *    |                                                  |             |
 *    | signed_certificate_timestamp [RFC6962]           |  CH, CR, CT |
 *    |                                                  |             |
 *    | client_certificate_type [RFC7250]                |      CH, EE |
 *    |                                                  |             |
 *    | server_certificate_type [RFC7250]                |      CH, EE |
 *    |                                                  |             |
 *    | padding [RFC7685]                                |          CH |
 *    |                                                  |             |
 *    | key_share (RFC 8446)                             | CH, SH, HRR |
 *    |                                                  |             |
 *    | pre_shared_key (RFC 8446)                        |      CH, SH |
 *    |                                                  |             |
 *    | psk_key_exchange_modes (RFC 8446)                |          CH |
 *    |                                                  |             |
 *    | early_data (RFC 8446)                            | CH, EE, NST |
 *    |                                                  |             |
 *    | cookie (RFC 8446)                                |     CH, HRR |
 *    |                                                  |             |
 *    | supported_versions (RFC 8446)                    | CH, SH, HRR |
 *    |                                                  |             |
 *    | certificate_authorities (RFC 8446)               |      CH, CR |
 *    |                                                  |             |
 *    | oid_filters (RFC 8446)                           |          CR |
 *    |                                                  |             |
 *    | post_handshake_auth (RFC 8446)                   |          CH |
 *    |                                                  |             |
 *    | signature_algorithms_cert (RFC 8446)             |      CH, CR |
 *    +--------------------------------------------------+-------------+
 * </pre>
 * <p/>
 * When multiple extensions of different types are present, the
 * extensions MAY appear in any order, with the exception of
 * "pre_shared_key" (Section 4.2.11) which MUST be the last extension in
 * the ClientHello (but can appear anywhere in the ServerHello
 * extensions block).  There MUST NOT be more than one extension of the
 * same type in a given extension block.
 * <p/>
 * In TLS 1.3, unlike TLS 1.2, extensions are negotiated for each
 * handshake even when in resumption-PSK mode.  However, 0-RTT
 * parameters are those negotiated in the previous handshake; mismatches
 * may require rejecting 0-RTT (see Section 4.2.10).
 * <p/>
 * There are subtle (and not so subtle) interactions that may occur in
 * this protocol between new features and existing features which may
 * result in a significant reduction in overall security.  The following
 * considerations should be taken into account when designing new
 * extensions:
 * <ul>
 *     <li>
 *         Some cases where a server does not agree to an extension are error
 *         conditions (e.g., the handshake cannot continue), and some are
 *         simply refusals to support particular features.  In general, error
 *         alerts should be used for the former and a field in the server
 *         extension response for the latter.
 *     </li>
 *     <li>
 *         Extensions should, as far as possible, be designed to prevent any
 *         attack that forces use (or non-use) of a particular feature by
 *         manipulation of handshake messages.  This principle should be
 *         followed regardless of whether the feature is believed to cause a
 *         security problem.  Often the fact that the extension fields are
 *         included in the inputs to the Finished message hashes will be
 *         sufficient, but extreme care is needed when the extension changes
 *         the meaning of messages sent in the handshake phase.  Designers
 *         and implementors should be aware of the fact that until the
 *         handshake has been authenticated, active attackers can modify
 *         messages and insert, remove, or replace extensions.
 *    </li>
 * </ul>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2">TLS 1.3 Spec/Section 4.2</a>
 */
public enum ExtensionType {

    /**
     * @see ServerNameIndicationExtension
     */
    SERVER_NAME( 0 ),                             /* RFC 6066 */
    MAX_FRAGMENT_LENGTH( 1 ),                     /* RFC 6066 */
    /**
     * RFC 6066
     *
     * @see StatusRequestExtensionBase
     * @see StatusRequestOcspExtension
     */
    STATUS_REQUEST( 5 ),

    /**
     * RFC 8422, 7919
     *
     * @see SupportedGroupsExtension
     */
    SUPPORTED_GROUPS( 10 ),
    /**
     * RFC 8446
     *
     * @see SignatureAlgorithmsExtension
     */
    SIGNATURE_ALGORITHMS( 13 ),
    USE_SRTP( 14 ),                               /* RFC 5764 */
    HEARTBEAT( 15 ),                              /* RFC 6520 */
    /**
     * RFC 7301
     *
     * @see ApplicationLayerProtocolNegotiationExtension
     */
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION( 16 ),
    SIGNED_CERTIFICATE_TIMESTAMP( 18 ),           /* RFC 6962 */

    CLIENT_CERTIFICATE_TYPE( 19 ),                /* RFC 7250 */
    SERVER_CERTIFICATE_TYPE( 20 ),                /* RFC 7250 */

    PADDING( 21 ),                                /* RFC 7685 */

    /**
     * RFC 8446
     *
     * @see PreSharedKeyExtensionBase
     * @see PreSharedKeyClientHelloExtension
     * @see PreSharedKeyServerHelloExtension
     */
    PRE_SHARED_KEY( 41 ),
    /**
     * RFC 8446
     *
     * @see EarlyDataIndicationExtension
     */
    EARLY_DATA( 42 ),
    /**
     * RFC 8446
     *
     * @see ClientSupportedVersionsExtension
     * @see ServerSupportedVersionsExtension
     */
    SUPPORTED_VERSIONS( 43 ),
    /**
     * RFC 8446
     *
     * @see CookieExtension
     */
    COOKIE( 44 ),
    /**
     * RFC 8446
     *
     * @see PskKeyExchangeModeExtension
     */
    PSK_KEY_EXCHANGE_MODES( 45 ),
    /**
     * RFC 8446
     *
     * @see CertificateAuthoritiesExtension
     */
    CERTIFICATE_AUTHORITIES( 47 ),
    /**
     * RFC 8446
     *
     * @see OidFilterExtension
     */
    OID_FILTERS( 48 ),
    /**
     * RFC 8446
     *
     * @see PostHandshakeClientAuthExtension
     */
    POST_HANDSHAKE_AUTH( 49 ),
    /**
     * RFC 8446
     */
    SIGNATURE_ALGORITHMS_CERT( 50 ),
    /**
     * RFC 8446
     *
     * @see KeyShareExtensionBase
     * @see KeyShareClientHelloExtension
     * @see KeyShareServerHelloExtension
     * @see KeyShareHelloRetryRequestExtension
     */
    KEY_SHARE( 51 ),

    /**
     * RFC 5746
     */
    RENEGOTIATION_INFO( 65281 /*0xff01*/ ),

    // QUIC Specifics:
    QUIC_TRANSPORT_PARAMETERS( 65445 /* 0xffa5 */ )

    // HIGHEST_VALUE( 65535 )
    ;

    @Getter
    private final long value;

    ExtensionType( long value ) {this.value = value;}

    public static ExtensionType findByValue( int value ) {
        for ( ExtensionType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

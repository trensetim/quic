package com.timtrense.quic.tls.handshake;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionCarryingHandshake;
import com.timtrense.quic.tls.HandshakeType;
import com.timtrense.quic.tls.extensions.EarlyDataIndicationExtension;

/**
 * <pre>
 * struct {
 *     uint32 ticket_lifetime;
 *     uint32 ticket_age_add;
 *     opaque ticket_nonce<0..255>;
 *     opaque ticket<1..2^16-1>;
 *     Extension extensions<0..2^16-2>;
 * } NewSessionTicket;
 * </pre>
 * <p/>
 * At any time after the server has received the client Finished
 * message, it MAY send a NewSessionTicket message.  This message
 * creates a unique association between the ticket value and a secret
 * PSK derived from the resumption master secret (see Section 7).
 * <p/>
 * The client MAY use this PSK for future handshakes by including the
 * ticket value in the "pre_shared_key" extension in its ClientHello
 * (Section 4.2.11).  Servers MAY send multiple tickets on a single
 * connection, either immediately after each other or after specific
 * events (see Appendix C.4).  For instance, the server might send a new
 * ticket after post-handshake authentication in order to encapsulate
 * the additional client authentication state.  Multiple tickets are
 * useful for clients for a variety of purposes, including:
 * <ul>
 *     <li>
 *         Opening multiple parallel HTTP connections.
 *     </li>
 *     <li>
 *         Performing connection racing across interfaces and address
 *       families via (for example) Happy Eyeballs [RFC8305] or related
 *       techniques.
 *     </li>
 * </ul>
 * <p/>
 * Any ticket MUST only be resumed with a cipher suite that has the same
 * KDF hash algorithm as that used to establish the original connection.
 * <p/>
 * Clients MUST only resume if the new SNI value is valid for the server
 * certificate presented in the original session and SHOULD only resume
 * if the SNI value matches the one used in the original session.  The
 * latter is a performance optimization: normally, there is no reason to
 * expect that different servers covered by a single certificate would
 * be able to accept each other's tickets; hence, attempting resumption
 * in that case would waste a single-use ticket.  If such an indication
 * is provided (externally or by any other means), clients MAY resume
 * with a different SNI value.
 * <p/>
 * On resumption, if reporting an SNI value to the calling application,
 * implementations MUST use the value sent in the resumption ClientHello
 * rather than the value sent in the previous session.  Note that if a
 * server implementation declines all PSK identities with different SNI
 * values, these two values are always the same.
 * <p/>
 * Note: Although the resumption master secret depends on the client's
 * second flight, a server which does not request client authentication
 * MAY compute the remainder of the transcript independently and then
 * send a NewSessionTicket immediately upon sending its Finished rather
 * than waiting for the client Finished.  This might be appropriate in
 * cases where the client is expected to open multiple TLS connections
 * in parallel and would benefit from the reduced overhead of a
 * resumption handshake, for example.
 * <p/>
 * The PSK associated with the ticket is computed as:
 * <pre>
 *      HKDF-Expand-Label(resumption_master_secret,
 *                         "resumption", ticket_nonce, Hash.length)
 * </pre>
 * <p/>
 * Because the ticket_nonce value is distinct for each NewSessionTicket
 * message, a different PSK will be derived for each ticket.
 * <p/>
 * Note that in principle it is possible to continue issuing new tickets
 * which indefinitely extend the lifetime of the keying material
 * originally derived from an initial non-PSK handshake (which was most
 * likely tied to the peer's certificate).  It is RECOMMENDED that
 * implementations place limits on the total lifetime of such keying
 * material; these limits should take into account the lifetime of the
 * peer's certificate, the likelihood of intervening revocation, and the
 * time since the peer's online CertificateVerify signature.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.6.1">TLS 1.3 Spec/Section 4.6.1</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class NewSessionTicket extends PostHandshakeMessage implements ExtensionCarryingHandshake {

    /**
     * uint32
     * <p/>
     * Indicates the lifetime in seconds as a 32-bit
     * unsigned integer in network byte order from the time of ticket
     * issuance.  Servers MUST NOT use any value greater than
     * 604800 seconds (7 days).  The value of zero indicates that the
     * ticket should be discarded immediately.  Clients MUST NOT cache
     * tickets for longer than 7 days, regardless of the ticket_lifetime,
     * and MAY delete tickets earlier based on local policy.  A server
     * MAY treat a ticket as valid for a shorter period of time than what
     * is stated in the ticket_lifetime.
     */
    private long ticketLifetime;

    /**
     * uint32
     * <p/>
     * A securely generated, random 32-bit value that is
     * used to obscure the age of the ticket that the client includes in
     * the "pre_shared_key" extension.  The client-side ticket age is
     * added to this value modulo 2^32 to obtain the value that is
     * transmitted by the client.  The server MUST generate a fresh value
     * for each ticket it sends.
     */
    private long ticketAgeAdd;

    /**
     * A per-ticket value that is unique across all tickets
     * issued on this connection.
     * <p/>
     * <b>Length is 0..255</b>
     * <p/>
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private byte[] ticketNonce = new byte[0];

    /**
     * The value of the ticket to be used as the PSK identity.  The
     * ticket itself is an opaque label.  It MAY be either a database
     * lookup key or a self-encrypted and self-authenticated value.
     * <p/>
     * <b>Length is 1..2^16-1</b>
     * <p/>
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private byte[] ticket = new byte[0];

    /**
     * A set of extension values for the ticket.  The
     * "Extension" format is defined in Section 4.2.  Clients MUST ignore
     * unrecognized extensions.
     * <p/>
     * The sole extension currently defined for NewSessionTicket is
     * "early_data", indicating that the ticket may be used to send 0-RTT
     * data (Section 4.2.10).  It contains the following value:
     * <p/>
     * <b>Implementation Note: the field will be initialized to an LENGTH = 1 {@link ArrayList} upon instantiation,
     * because the sole extension currently defined is {@link EarlyDataIndicationExtension}</b>
     */
    private @NonNull List<Extension> extensions = new ArrayList<>( 1 );

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.NEW_SESSION_TICKET;
    }
}

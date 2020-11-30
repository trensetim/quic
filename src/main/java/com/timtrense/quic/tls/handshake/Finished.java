package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.ExtendedHandshake;
import com.timtrense.quic.tls.Handshake;
import com.timtrense.quic.tls.HandshakeType;

/**
 * The Finished message is the final message in the Authentication
 * Block.  It is essential for providing authentication of the handshake
 * and of the computed keys.
 * <p/>
 * Recipients of Finished messages MUST verify that the contents are
 * correct and if incorrect MUST terminate the connection with a
 * "decrypt_error" alert.
 * <p/>
 * Once a side has sent its Finished message and has received and
 * validated the Finished message from its peer, it may begin to send
 * and receive Application Data over the connection.  There are two
 * settings in which it is permitted to send data prior to receiving the
 * peer's Finished:
 * <ol>
 *     <li>
 *         Clients sending 0-RTT data as described in Section 4.2.10.
 *     </li>
 *     <li>
 *         Servers MAY send data after sending their first flight, but
 *        because the handshake is not yet complete, they have no assurance
 *        of either the peer's identity or its liveness (i.e., the
 *        ClientHello might have been replayed).
 *     </li>
 * </ol>
 *
 * <p/>
 * The key used to compute the Finished message is computed from the
 * Base Key defined in Section 4.4 using HKDF (see Section 7.1).
 * Specifically:
 * <pre>
 *     finished_key =
 *        HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
 * </pre>
 * <p/>
 * Structure of this message:
 * <pre>
 * struct {
 *     opaque verify_data[Hash.length];
 * } Finished;
 * </pre>
 * The verify_data value is computed as follows:
 * <pre>
 *  verify_data = HMAC(
 *                      finished_key,
 *                      Transcript-Hash(
 *                            Handshake Context,
 *                            Certificate*,
 *                            CertificateVerify*
 *                      )
 *  )
 *       * Only included if present.
 * </pre>
 * <p/>
 * HMAC [RFC2104] uses the Hash algorithm for the handshake.  As noted
 * above, the HMAC input can generally be implemented by a running hash,
 * i.e., just the handshake hash at this point.
 * <p/>
 * In previous versions of TLS, the verify_data was always 12 octets
 * long.  In TLS 1.3, it is the size of the HMAC output for the Hash
 * used for the handshake.
 * <p/>
 * Note: Alerts and any other non-handshake record types are not
 * handshake messages and are not included in the hash computations.
 * <p/>
 * Any records following a Finished message MUST be encrypted under the
 * appropriate application traffic key as described in Section 7.2.  In
 * particular, this includes any alerts sent by the server in response
 * to client Certificate and CertificateVerify messages.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.4">TLS 1.3 Spec/Section 4.4.4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class Finished extends Handshake {

    /**
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private byte[] verifyData = new byte[0];

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.FINISHED;
    }
}

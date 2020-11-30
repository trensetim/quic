package com.timtrense.quic.tls;

import lombok.Data;

/**
 * The PSK binder value forms a binding between a PSK and the current
 * handshake, as well as a binding between the handshake in which the
 * PSK was generated (if via a NewSessionTicket message) and the current
 * handshake.  Each entry in the binders list is computed as an HMAC
 * over a transcript hash (see Section 4.4.1) containing a partial
 * ClientHello up to and including the PreSharedKeyExtension.identities
 * field.  That is, it includes all of the ClientHello but not the
 * binders list itself.  The length fields for the message (including
 * the overall length, the length of the extensions block, and the
 * length of the "pre_shared_key" extension) are all set as if binders
 * of the correct lengths were present.
 * <p/>
 * The PskBinderEntry is computed in the same way as the Finished
 * message (Section 4.4.4) but with the BaseKey being the binder_key
 * derived via the key schedule from the corresponding PSK which is
 * being offered (see Section 7.1).
 * <p/>
 * If the handshake includes a HelloRetryRequest, the initial
 * ClientHello and HelloRetryRequest are included in the transcript
 * along with the new ClientHello.  For instance, if the client sends
 * ClientHello1, its binder will be computed over:
 * <pre>
 *     Transcript-Hash(Truncate(ClientHello1))
 * </pre>
 * Where Truncate() removes the binders list from the ClientHello.
 * <p/>
 * If the server responds with a HelloRetryRequest and the client then
 * sends ClientHello2, its binder will be computed over:
 * <pre>
 *     Transcript-Hash(
 *                     ClientHello1,
 *                     HelloRetryRequest,
 *                     Truncate(ClientHello2)
 *     )
 * </pre>
 * The full ClientHello1/ClientHello2 is included in all other handshake
 * hash computations.  Note that in the first flight,
 * Truncate(ClientHello1) is hashed directly, but in the second flight,
 * ClientHello1 is hashed and then reinjected as a "message_hash"
 * message, as described in Section 4.4.1.
 */
@Data
public class PskBinderEntry {

    /**
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private byte[] entry = new byte[0];
}

package com.timtrense.quic;

/**
 * It is necessary to limit the amount of data that a receiver could
 * buffer, to prevent a fast sender from overwhelming a slow receiver,
 * or to prevent a malicious sender from consuming a large amount of
 * memory at a receiver.  To enable a receiver to limit memory
 * commitment to a connection and to apply back pressure on the sender,
 * streams are flow controlled both individually and as an aggregate.  A
 * QUIC receiver controls the maximum amount of data the sender can send
 * on a stream at any time, as described in Section 4.1 and Section 4.2.
 *
 * Similarly, to limit concurrency within a connection, a QUIC endpoint
 * controls the maximum cumulative number of streams that its peer can
 * initiate, as described in Section 4.6.
 *
 * Data sent in CRYPTO frames is not flow controlled in the same way as
 * stream data.  QUIC relies on the cryptographic protocol
 * implementation to avoid excessive buffering of data; see [QUIC-TLS].
 * To avoid excessive buffering at multiple layers, QUIC implementations
 * SHOULD provide an interface for the cryptographic protocol
 * implementation to communicate its buffering limits.
 *
 * See {@link CreditBasedFlowControl} for details on flow control in QUIC.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-4">QUIC Spec/Section 4</a>
 */
public interface FlowControl {

    /**
     * Checks the implementation whether the caller would be allowed to send AT LEAST the queried amount of
     * data to the peer.
     *
     * The call is inherently NOT thread-safe unless nobody else is sending on the referred connection,
     * because the connection implementation MUST guarantee that the transferable amount of data does NEVER
     * decrease while no data is being sent. Only sending some data MAY decrease the
     * currently transferable amount of data.
     *
     * As time passes, the peer MAY allow this endpoint to send more data. This implies that the transferable
     * amount of data MAY increase out of control of the caller and MAY even be increased right after a call
     * to this function.
     *
     * @param numberOfBytes the amount the caller tries to send
     * @return true if the flow control allows sending at least that amount of data NOW in its current state,
     * false otherwise
     */
    boolean canSend( int numberOfBytes );
}

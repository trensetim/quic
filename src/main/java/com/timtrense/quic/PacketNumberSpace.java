package com.timtrense.quic;

/**
 * For details on packet numbers, see {@link PacketNumber}.
 *
 * Conceptually, a packet number space is the context in which a packet
 * can be processed and acknowledged.  Initial packets can only be sent
 * with Initial packet protection keys and acknowledged in packets that
 * are also Initial packets.  Similarly, Handshake packets are sent at
 * the Handshake encryption level and can only be acknowledged in
 * Handshake packets.
 *
 * This enforces cryptographic separation between the data sent in the
 * different packet number spaces.  Packet numbers in each space start
 * at packet number 0.  Subsequent packets sent in the same packet
 * number space MUST increase the packet number by at least one.
 *
 * 0-RTT and 1-RTT data exist in the same packet number space to make
 * loss recovery algorithms easier to implement between the two packet
 * types.
 *
 * A QUIC endpoint MUST NOT reuse a packet number within the same packet
 * number space in one connection.  If the packet number for sending
 * reaches 2^62 - 1, the sender MUST close the connection without
 * sending a CONNECTION_CLOSE frame or any further packets; an endpoint
 * MAY send a Stateless Reset (Section 10.3) in response to further
 * packets that it receives.
 *
 * A receiver MUST discard a newly unprotected packet unless it is
 * certain that it has not processed another packet with the same packet
 * number from the same packet number space.  Duplicate suppression MUST
 * happen after removing packet protection for the reasons described in
 * Section 9.3 of [QUIC-TLS].
 *
 * Version Negotiation (Section 17.2.1) and Retry (Section 17.2.5)
 * packets do not include a packet number.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12.3">QUIC Spec/Section 12.3</a>
 */
public enum PacketNumberSpace {

    /**
     * All Initial packets (Section 17.2.2) are in this space
     */
    INITIAL,
    /**
     * All Handshake packets (Section 17.2.4) are in this space.
     */
    HANDSHAKE,
    /**
     * All 0-RTT (Section 17.2.3) and 1-RTT (Section 17.3) encrypted packets are in this space.
     */
    APPLICATION_DATA
}

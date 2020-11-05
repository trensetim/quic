package com.timtrense.quic;

/**
 * The packet number is an integer in the range 0 to 2^62-1.  This
 * number is used in determining the cryptographic nonce for packet
 * protection.  Each endpoint maintains a separate packet number for
 * sending and receiving.
 *
 * Packet numbers are limited to this range because they need to be
 * representable in whole in the Largest Acknowledged field of an ACK
 * frame (Section 19.3).  When present in a long or short header
 * however, packet numbers are reduced and encoded in 1 to 4 bytes; see
 * Section 17.1.
 *
 * Version Negotiation (Section 17.2.1) and Retry (Section 17.2.5)
 * packets do not include a packet number.
 *
 * Packet numbers are divided into 3 spaces in QUIC:
 *
 * <ul>
 *      <li>
 *          Initial space: All Initial packets (Section 17.2.2) are in this space.
 *      </li>
 *      <li>
 *          Handshake space: All Handshake packets (Section 17.2.4) are in this space.
 *      </li>
 *      <li>
 *          Application data space: All 0-RTT (Section 17.2.3)
 *              and 1-RTT (Section 17.3) encrypted packets are in this space.
 *      </li>
 * </ul>
 *
 * As described in [QUIC-TLS], each packet type uses different
 * protection keys.
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
 * Endpoints that track all individual packets for the purposes of
 * detecting duplicates are at risk of accumulating excessive state.
 * The data required for detecting duplicates can be limited by
 * maintaining a minimum packet number below which all packets are
 * immediately dropped.  Any minimum needs to account for large
 * variations in round trip time, which includes the possibility that a
 * peer might probe network paths with much larger round trip times; see
 * Section 9.
 *
 * <p/>
 * <h2>Encoding and Decoding</h2>
 * Packet numbers are integers in the range 0 to 2^62-1 (Section 12.3).
 * When present in long or short packet headers, they are encoded in 1
 * to 4 bytes.  The number of bits required to represent the packet
 * number is reduced by including only the least significant bits of the
 * packet number.
 *
 * The encoded packet number is protected as described in Section 5.4 of
 * [QUIC-TLS].
 *
 * Prior to receiving an acknowledgement for a packet number space, the
 * full packet number MUST be included; it is not to be truncated as
 * described below.
 *
 * After an acknowledgement is received for a packet number space, the
 * sender MUST use a packet number size able to represent more than
 * twice as large a range than the difference between the largest
 * acknowledged packet and packet number being sent.  A peer receiving
 * the packet will then correctly decode the packet number, unless the
 * packet is delayed in transit such that it arrives after many higher-
 * numbered packets have been received.  An endpoint SHOULD use a large
 * enough packet number encoding to allow the packet number to be
 * recovered even if the packet arrives after packets that are sent
 * afterwards.
 *
 * As a result, the size of the packet number encoding is at least one
 * bit more than the base-2 logarithm of the number of contiguous
 * unacknowledged packet numbers, including the new packet.
 *
 * For example, if an endpoint has received an acknowledgment for packet
 * 0xabe8bc, sending a packet with a number of 0xac5c02 requires a
 * packet number encoding with 16 bits or more; whereas the 24-bit
 * packet number encoding is needed to send a packet with a number of
 * 0xace8fe.
 *
 * At a receiver, protection of the packet number is removed prior to
 * recovering the full packet number.  The full packet number is then
 * reconstructed based on the number of significant bits present, the
 * value of those bits, and the largest packet number received on a
 * successfully authenticated packet.  Recovering the full packet number
 * is necessary to successfully remove packet protection.
 *
 * Once header protection is removed, the packet number is decoded by
 * finding the packet number value that is closest to the next expected
 * packet.  The next expected packet is the highest received packet
 * number plus one.  For example, if the highest successfully
 * authenticated packet had a packet number of 0xa82f30ea, then a packet
 * containing a 16-bit value of 0x9b32 will be decoded as 0xa82f9b32.
 * Example pseudo-code for packet number decoding can be found in
 * Appendix A.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12.3">QUIC Spec/Section 12.3</a>
 */
public interface PacketNumber {

    /**
     * @return the packet number as a long value
     */
    long getValue();
}

package com.timtrense.quic;

/**
 * UDP datagram payload.
 *
 * QUIC endpoints communicate by exchanging packets.  Packets have
 * confidentiality and integrity protection; see Section 12.1.  Packets
 * are carried in UDP datagrams; see Section 12.2.
 *
 * This version of QUIC uses the long packet header during connection
 * establishment; see Section 17.2.  Packets with the long header are
 * Initial (Section 17.2.2), 0-RTT (Section 17.2.3), Handshake
 * (Section 17.2.4), and Retry (Section 17.2.5).  Version negotiation
 * uses a version-independent packet with a long header; see
 * Section 17.2.1.
 *
 * Packets with the short header are designed for minimal overhead and
 * are used after a connection is established and 1-RTT keys are
 * available; see Section 17.3.
 *
 * <p/>
 * <h2>Protected Packets</h2>
 * QUIC packets have different levels of cryptographic protection based
 * on the type of packet.  Details of packet protection are found in
 * [QUIC-TLS]; this section includes an overview of the protections that
 * are provided.
 *
 * Version Negotiation packets have no cryptographic protection; see
 * [QUIC-INVARIANTS].
 *
 * Retry packets use an authenticated encryption with associated data
 * function (AEAD; [AEAD]) to protect against accidental modification.
 *
 * Initial packets use an AEAD, the keys for which are derived using a
 * value that is visible on the wire.  Initial packets therefore do not
 * have effective confidentiality protection.  Initial protection exists
 * to ensure that the sender of the packet is on the network path.  Any
 * entity that receives an Initial packet from a client can recover the
 * keys that will allow them to both read the contents of the packet and
 * generate Initial packets that will be successfully authenticated at
 * either endpoint.
 *
 * All other packets are protected with keys derived from the
 * cryptographic handshake.  The cryptographic handshake ensures that
 * only the communicating endpoints receive the corresponding keys for
 * Handshake, 0-RTT, and 1-RTT packets.  Packets protected with 0-RTT
 * and 1-RTT keys have strong confidentiality and integrity protection.
 *
 * The Packet Number field that appears in some packet types has
 * alternative confidentiality protection that is applied as part of
 * header protection; see Section 5.4 of [QUIC-TLS] for details.  The
 * underlying packet number increases with each packet sent in a given
 * packet number space; see Section 12.3 for details.
 *
 * <p/>
 * <h2>Coalescing Packets</h2>
 * Initial (Section 17.2.2), 0-RTT (Section 17.2.3), and Handshake
 * (Section 17.2.4) packets contain a Length field that determines the
 * end of the packet.  The length includes both the Packet Number and
 * Payload fields, both of which are confidentiality protected and
 * initially of unknown length.  The length of the Payload field is
 * learned once header protection is removed.
 *
 * Using the Length field, a sender can coalesce multiple QUIC packets
 * into one UDP datagram.  This can reduce the number of UDP datagrams
 * needed to complete the cryptographic handshake and start sending
 * data.  This can also be used to construct PMTU probes; see
 * Section 14.4.1.  Receivers MUST be able to process coalesced packets.
 *
 * Coalescing packets in order of increasing encryption levels (Initial,
 * 0-RTT, Handshake, 1-RTT; see Section 4.1.4 of [QUIC-TLS]) makes it
 * more likely the receiver will be able to process all the packets in a
 * single pass.  A packet with a short header does not include a length,
 * so it can only be the last packet included in a UDP datagram.  An
 * endpoint SHOULD include multiple frames in a single packet if they
 * are to be sent at the same encryption level, instead of coalescing
 * multiple packets at the same encryption level.
 *
 * Receivers MAY route based on the information in the first packet
 * contained in a UDP datagram.  Senders MUST NOT coalesce QUIC packets
 * with different connection IDs into a single UDP datagram.  Receivers
 * SHOULD ignore any subsequent packets with a different Destination
 * Connection ID than the first packet in the datagram.
 *
 * Every QUIC packet that is coalesced into a single UDP datagram is
 * separate and complete.  The receiver of coalesced QUIC packets MUST
 * individually process each QUIC packet and separately acknowledge
 * them, as if they were received as the payload of different UDP
 * datagrams.  For example, if decryption fails (because the keys are
 * not available or any other reason), the receiver MAY either discard
 * or buffer the packet for later processing and MUST attempt to process
 * the remaining packets.
 *
 * Retry packets (Section 17.2.5), Version Negotiation packets
 * (Section 17.2.1), and packets with a short header (Section 17.3) do
 * not contain a Length field and so cannot be followed by other packets
 * in the same UDP datagram.  Note also that there is no situation where
 * a Retry or Version Negotiation packet is coalesced with another
 * packet.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12">QUIC Spec/Section 12</a>
 */
public interface Packet {

    /**
     * The Destination Connection ID is a
     * connection ID that is chosen by the intended recipient of the
     * packet. See Section 5.1 for more details.
     *
     * @return the destination connection id
     */
    ConnectionId getDestinationConnectionId();

    // packet number is hold in {@link NumberedPacket}

    /**
     * Attention: this function may return a valid number that is not actually accurate
     * IF AND ONLY IF <code>{@link Frame#isValid()} == false</code> for ANY contained frame (if this packet has any)
     * OR <code>{@link #isPacketValid()} == false</code>
     *
     * @return the length of this packet in bytes or -1 if the packet is either invalid or of unknown length
     * @throws NullPointerException if the packet contains required fields with null value
     *                              OR any contained frame does
     */
    long getPacketLength();

    /**
     * Checks the header of this packet but NOT whether all packed frames are valid too.
     *
     * @return true if all necessary data for that packet is present NOT including the payload
     */
    boolean isPacketValid();
}

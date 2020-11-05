package com.timtrense.quic;

/**
 * This interface combines all types of {@link Packet Packets} that hold a packet number
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.1">QUIC Spec/Section 17.1</a>
 * @see Packet
 */
public interface NumberedPacket extends Packet {

    /**
     * The packet number field is 1 to 4 bytes long.
     *
     * @return the encoded length of the packet number in bytes
     */
    int getPacketNumberLength();

    /**
     * The packet number field is 1 to 4 bytes long.  The
     * packet number has confidentiality protection separate from packet
     * protection, as described in Section 5.4 of [QUIC-TLS].  The length
     * of the packet number field is encoded in Packet Number Length
     * field.  See Section 17.1 for details.
     *
     * @return the actual packet number
     */
    PacketNumber getPacketNumber();
}

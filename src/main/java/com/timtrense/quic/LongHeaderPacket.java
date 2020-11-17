package com.timtrense.quic;

/**
 * Long headers are used for packets that are sent prior to the
 * establishment of 1-RTT keys.  Once 1-RTT keys are available, a sender
 * switches to sending packets using the short header (Section 17.3).
 * The long form allows for special packets - such as the Version
 * Negotiation packet - to be represented in this uniform fixed-length
 * packet format.
 *
 * The header form bit, Destination and Source Connection ID lengths,
 * Destination and Source Connection ID fields, and Version fields of a
 * long header packet are version-independent.  The other fields in the
 * first byte are version-specific.  See [QUIC-INVARIANTS] for details
 * on how packets from different versions of QUIC are interpreted.
 *
 * The interpretation of the fields and the payload are specific to a
 * version and packet type.
 *
 * <p/>
 * <h2>Structure of the first byte</h2>
 * <ul>
 *     <li>
 *         Header Form:  The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers.
 *     </li>
 *     <li>
 *         Fixed Bit:  The next bit (0x40) of byte 0 is set to 1.  Packets
 *       containing a zero value for this bit are not valid packets in this
 *       version and MUST be discarded.
 *     </li>
 *     <li>
 *          Long Packet Type:  The next two bits (those with a mask of 0x30) of
 *       byte 0 contain a packet type.  Packet types are listed in Table 5.
 *     </li>
 *     <li>
 *         Type-Specific Bits:  The lower four bits (those with a mask of 0x0f)
 *       of byte 0 are type-specific.
 *     </li>
 * </ul>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2">QUIC Spec/Section 17.2</a>
 */
public interface LongHeaderPacket extends Packet {

    /**
     * bitmask to extract the long packet type from the flags
     */
    int FLAGS_TYPE_MASK = 0b00110000;

    /**
     * Header Form (1) = 1,
     * Fixed Bit (1) = 1,
     * Long Packet Type (2),
     * Type-Specific Bits (4)
     *
     * @return the first 8 bits of the packet in network byte order (that is big-endian)
     */
    byte getFlags();

    /**
     * @return the second 4 bits of the packet in network byte order (that is big-endian)
     */
    default byte getTypeSpecificBits() {
        return (byte)( getFlags() & 0b00001111 );
    }

    /**
     * @return the type of this long header packet
     */
    default LongHeaderPacketType getType() {
        int typeId = getFlags();
        typeId >>= 4;
        typeId &= 0b00000011;
        return LongHeaderPacketType.findById( typeId );
    }

    /**
     * The QUIC Version is a 32-bit field that follows the first
     * byte.  This field indicates the version of QUIC that is in use and
     * determines how the rest of the protocol fields are interpreted.
     *
     * @return the quic version
     */
    ProtocolVersion getVersion();

    /**
     * The byte following the version
     * contains the length in bytes of the Destination Connection ID
     * field that follows it.  This length is encoded as an 8-bit
     * unsigned integer.  In QUIC version 1, this value MUST NOT exceed
     * 20.  Endpoints that receive a version 1 long header with a value
     * larger than 20 MUST drop the packet.  In order to properly form a
     * Version Negotiation packet, servers SHOULD be able to read longer
     * connection IDs from other QUIC versions.
     *
     * @return the encoded length of the destination connection id in bytes
     */
    long getDestinationConnectionIdLength();

    /**
     * The byte following the Destination
     * Connection ID contains the length in bytes of the Source
     * Connection ID field that follows it.  This length is encoded as a
     * 8-bit unsigned integer.  In QUIC version 1, this value MUST NOT
     * exceed 20 bytes.  Endpoints that receive a version 1 long header
     * with a value larger than 20 MUST drop the packet.  In order to
     * properly form a Version Negotiation packet, servers SHOULD be able
     * to read longer connection IDs from other QUIC versions.
     *
     * @return the encoded length of the source connection id in bytes
     */
    long getSourceConnectionIdLength();

    /**
     * The Source Connection ID field follows the
     * Source Connection ID Length field, which indicates the length of
     * this field.  Section 7.2 describes the use of this field in more
     * detail.
     *
     * @return the source connection id
     */
    ConnectionId getSourceConnectionId();
}

package com.timtrense.quic;

/**
 * This version of QUIC defines a single packet type that uses the short
 * packet header.
 *
 * The short header can be used after the version and 1-RTT keys are
 * negotiated.
 *
 * The header form bit and the connection ID field of a short header
 * packet are version-independent. The remaining fields are specific to
 * the selected QUIC version. See [QUIC-INVARIANTS] for details on how
 * packets from different versions of QUIC are interpreted.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.3">QUIC Spec/Section 17.3</a>
 */
public interface ShortHeaderPacket extends NumberedPacket, FrameContainingPacket {

    /**
     * Header Form (1) = 0,
     * Fixed Bit (1) = 1,
     * Spin Bit (1),
     * Reserved Bits (2),
     * Key Phase (1),
     * Packet Number Length (2)
     *
     * @return the first 8 bits of the packet in network byte order (that is big-endian)
     */
    byte getFlags();

    /**
     * The latency spin bit enables passive latency monitoring from
     * observation points on the network path throughout the duration of a
     * connection.  The spin bit is only present in the short packet header,
     * since it is possible to measure the initial RTT of a connection by
     * observing the handshake.  Therefore, the spin bit is available after
     * version negotiation and connection establishment are completed.  On-
     * path measurement and use of the latency spin bit is further discussed
     * in [QUIC-MANAGEABILITY].
     *
     * The spin bit is an OPTIONAL feature of QUIC.  A QUIC stack that
     * chooses to support the spin bit MUST implement it as specified in
     * this section.
     *
     * Each endpoint unilaterally decides if the spin bit is enabled or
     * disabled for a connection.  Implementations MUST allow administrators
     * of clients and servers to disable the spin bit either globally or on
     * a per-connection basis.  Even when the spin bit is not disabled by
     * the administrator, endpoints MUST disable their use of the spin bit
     * for a random selection of at least one in every 16 network paths, or
     * for one in every 16 connection IDs.  As each endpoint disables the
     * spin bit independently, this ensures that the spin bit signal is
     * disabled on approximately one in eight network paths.
     *
     * When the spin bit is disabled, endpoints MAY set the spin bit to any
     * value, and MUST ignore any incoming value.  It is RECOMMENDED that
     * endpoints set the spin bit to a random value either chosen
     * independently for each packet or chosen independently for each
     * connection ID.
     *
     * If the spin bit is enabled for the connection, the endpoint maintains
     * a spin value for each network path and sets the spin bit in the short
     * header to the currently stored value when a packet with a short
     * header is sent on that path.  The spin value is initialized to 0 in
     * the endpoint for each network path.  Each endpoint also remembers the
     * highest packet number seen from its peer on each path.
     *
     * When a server receives a short header packet that increases the
     * highest packet number seen by the server from the client on a given
     * network path, it sets the spin value for that path to be equal to the
     * spin bit in the received packet.
     *
     * When a client receives a short header packet that increases the
     * highest packet number seen by the client from the server on a given
     * network path, it sets the spin value for that path to the inverse of
     * the spin bit in the received packet.
     *
     * An endpoint resets the spin value for a network path to zero when
     * changing the connection ID being used on that network path.
     *
     * With this mechanism, the server reflects the spin value received,
     * while the client 'spins' it after one RTT.  On-path observers can
     * measure the time between two spin bit toggle events to estimate the
     * end-to-end RTT of a connection.
     *
     * @return true if the spin bit (flags-3rd-most-significant-bit) is set, false otherwise
     */
    default boolean getSpinBitValue() {
        return ( getFlags() & 0b00100000 ) != 0;
    }

    /**
     * The next bit (0x04) of byte 0 indicates the key phase,
     * which allows a recipient of a packet to identify the packet
     * protection keys that are used to protect the packet.  See
     * [QUIC-TLS] for details.  This bit is protected using header
     * protection; see Section 5.4 of [QUIC-TLS].
     *
     * @return true if the key-phase bit (flags-6th-most-significant-bit) is set, false otherwise
     */
    default boolean getKeyPhaseBitValue() {
        return ( getFlags() & 0b00000100 ) != 0;
    }

    /**
     * convenience-function for holding naming conventions for boolean-Getters on the {@link #getKeyPhaseBitValue()}
     *
     * @return the forwarded value of {@link #getKeyPhaseBitValue()} without side effects
     */
    default boolean isKeyPhase() {
        return getKeyPhaseBitValue();
    }

    /**
     * The least significant two bits (those with a
     * mask of 0x03) of byte 0 contain the length of the packet number,
     * encoded as an unsigned, two-bit integer that is one less than the
     * length of the packet number field in bytes.  That is, the length
     * of the packet number field is the value of this field, plus one.
     * These bits are protected using header protection; see Section 5.4
     * of [QUIC-TLS].
     *
     * @return the number of bytes used to encode the packet number
     */
    @Override
    default int getPacketNumberLength() {
        return ( getFlags() & 0b00000011 );
    }

    /**
     * Attention:
     * QUOTE: The length of the Destination Connection ID field is expected to be known to endpoints.
     * FROM:  https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-5.1
     *
     * @return the packets length in bytes SUBTRACTED BY THE length of the connection id
     * which callers MUST explicitly add
     * @see Packet#getPacketLength()
     */
    @Override
    default long getPacketLength() {
        long sum = 1;// flags
        sum += getPacketNumberLength();
        /*
        QUOTE: The length of the Destination Connection ID field is expected to be known to endpoints.
        FROM    https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-5.1
         */
        sum += getLongPayloadLength();

        return sum;
    }

    /**
     * Attention:
     * QUOTE: The length of the Destination Connection ID field is expected to be known to endpoints.
     * FROM:  https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-5.1
     *
     * @return the packets length in bytes SUBTRACTED BY THE length of the connection id
     * which callers MUST explicitly add
     * @see Packet#getHeaderLength()
     */
    @Override
    default long getHeaderLength() {
        long sum = 1;// flags
        sum += getPacketNumberLength();
        return sum;
    }
}

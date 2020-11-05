package com.timtrense.quic;

import java.util.List;

/**
 * A Version Negotiation packet is inherently not version-specific.
 * Upon receipt by a client, it will be identified as a Version
 * Negotiation packet based on the Version field having a value of 0.
 *
 * The Version Negotiation packet is a response to a client packet that
 * contains a version that is not supported by the server, and is only
 * sent by servers.
 *
 * The layout of a Version Negotiation packet is:
 * <pre>
 * Version Negotiation Packet {
 *      Header Form (1) = 1,
 *      Unused (7),
 *      Version (32) = 0,
 *      Destination Connection ID Length (8),
 *      Destination Connection ID (0..2040),
 *      Source Connection ID Length (8),
 *      Source Connection ID (0..2040),
 *      Supported Version (32) ...,
 * }
 * </pre>
 *
 * The value in the Unused field is selected randomly by the server.
 * Clients MUST ignore the value of this field.  Servers SHOULD set the
 * most significant bit of this field (0x40) to 1 so that Version
 * Negotiation packets appear to have the Fixed Bit field.
 *
 * The server MUST include the value from the Source Connection ID field
 * of the packet it receives in the Destination Connection ID field.
 * The value for Source Connection ID MUST be copied from the
 * Destination Connection ID of the received packet, which is initially
 * randomly selected by a client.  Echoing both connection IDs gives
 * clients some assurance that the server received the packet and that
 * the Version Negotiation packet was not generated by an off-path
 * attacker.
 *
 * Future versions of QUIC may have different requirements for the
 * lengths of connection IDs.  In particular, connection IDs might have
 * a smaller minimum length or a greater maximum length.  Version-
 * specific rules for the connection ID therefore MUST NOT influence a
 * server decision about whether to send a Version Negotiation packet.
 *
 * The remainder of the Version Negotiation packet is a list of 32-bit
 * versions that the server supports.
 *
 * A Version Negotiation packet is not acknowledged.  It is only sent in
 * response to a packet that indicates an unsupported version; see
 * Section 5.2.2.
 *
 * The Version Negotiation packet does not include the Packet Number and
 * Length fields present in other packets that use the long header form.
 * Consequently, a Version Negotiation packet consumes an entire UDP
 * datagram.
 *
 * A server MUST NOT send more than one Version Negotiation packet in
 * response to a single UDP datagram.
 *
 * See Section 6 for a description of the version negotiation process.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.1">QUIC Spec/Section 17.2.1</a>
 */
public interface VersionNegotiationPacket extends LongHeaderPacket {

    /**
     * The Version field of a Version Negotiation packet MUST be set to 0x00000000.
     *
     * @return always returns {@link ProtocolVersion#RESERVED_FOR_VERSION_NEGOTIATION}
     */
    @Override
    default ProtocolVersion getVersion() {
        return ProtocolVersion.RESERVED_FOR_VERSION_NEGOTIATION;
    }

    /**
     * @return all supported versions
     */
    List<ProtocolVersion> getSupportedVersions();
}

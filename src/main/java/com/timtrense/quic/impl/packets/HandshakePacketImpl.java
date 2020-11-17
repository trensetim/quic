package com.timtrense.quic.impl.packets;

import java.util.LinkedList;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameContainingPacket;
import com.timtrense.quic.LongHeaderPacket;
import com.timtrense.quic.NumberedPacket;
import com.timtrense.quic.PacketNumber;
import com.timtrense.quic.ProtocolVersion;
import com.timtrense.quic.VariableLengthInteger;

/**
 * A Handshake packet uses long headers with a type value of 0x2,
 * followed by the Length and Packet Number fields; see Section 17.2.
 * The first byte contains the Reserved and Packet Number Length bits;
 * see Section 17.2.  It is used to carry cryptographic handshake
 * messages and acknowledgments from the server and client.
 *
 * Once a client has received a Handshake packet from a server, it uses
 * Handshake packets to send subsequent cryptographic handshake messages
 * and acknowledgments to the server.
 *
 * The Destination Connection ID field in a Handshake packet contains a
 * connection ID that is chosen by the recipient of the packet; the
 * Source Connection ID includes the connection ID that the sender of
 * the packet wishes to use; see Section 7.2.
 *
 * Handshake packets are their own packet number space, and thus the
 * first Handshake packet sent by a server contains a packet number of
 * 0.
 *
 * The payload of this packet contains CRYPTO frames and could contain
 * PING, PADDING, or ACK frames.  Handshake packets MAY contain
 * CONNECTION_CLOSE frames of type 0x1c.  Endpoints MUST treat receipt
 * of Handshake packets with other frames as a connection error.
 *
 * Like Initial packets (see Section 17.2.2.1), data in CRYPTO frames
 * for Handshake packets is discarded - and no longer retransmitted -
 * when Handshake protection keys are discarded.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.4">QUIC Spec/Section 17.2.4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
@RequiredArgsConstructor
public class HandshakePacketImpl extends BaseLongHeaderPacket implements NumberedPacket, FrameContainingPacket {

    // private VariableLengthInteger length; // that is the #getPayloadLength()
    private PacketNumber packetNumber;
    private final @NonNull List<Frame> payload = new LinkedList<>();

    @Override
    public boolean isPacketValid() {
        return ( ( flags & 0b10000000 ) == 0b10000000 )
                && ( ( flags & 0b01000000 ) == 0b01000000 )
                && ( ( flags & 0b00110000 ) == 0b00100000 ) // LongHeaderPacketType.HANDSHAKE
                && ( ( flags & 0b00000011 ) != 0b00000000 )
                && ( version != null )
                && ( version != ProtocolVersion.RESERVED_FOR_VERSION_NEGOTIATION )
                && packetNumber != null;
    }

    @Override
    public int getPacketNumberLength() {
        return ( flags & 0b00000011 );
    }

    @Override
    public long getPacketLength() {
        long sum = super.getPacketLength();
        sum += getPacketNumberLength();
        VariableLengthInteger payloadLength = getPayloadLength();
        sum += payloadLength.getEncodedLengthInBytes();
        sum += payloadLength.getValue();
        return sum;
    }
}

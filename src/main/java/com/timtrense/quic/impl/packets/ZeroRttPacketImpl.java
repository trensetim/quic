package com.timtrense.quic.impl.packets;

import java.util.LinkedList;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameContainingPacket;
import com.timtrense.quic.NumberedPacket;
import com.timtrense.quic.PacketNumber;
import com.timtrense.quic.ProtocolVersion;
import com.timtrense.quic.VariableLengthInteger;

/**
 * A 0-RTT packet uses long headers with a type value of 0x1, followed
 * by the Length and Packet Number fields; see Section 17.2.  The first
 * byte contains the Reserved and Packet Number Length bits; see
 * Section 17.2.  A 0-RTT packet is used to carry "early" data from the
 * client to the server as part of the first flight, prior to handshake
 * completion.  As part of the TLS handshake, the server can accept or
 * reject this early data.
 *
 * See Section 2.3 of [TLS13] for a discussion of 0-RTT data and its
 * limitations.
 *
 * Packet numbers for 0-RTT protected packets use the same space as
 * 1-RTT protected packets.
 *
 * After a client receives a Retry packet, 0-RTT packets are likely to
 * have been lost or discarded by the server.  A client SHOULD attempt
 * to resend data in 0-RTT packets after it sends a new Initial packet.
 * New packet numbers MUST be used for any new packets that are sent; as
 * described in Section 17.2.5.3, reusing packet numbers could
 * compromise packet protection.
 *
 * A client only receives acknowledgments for its 0-RTT packets once the
 * handshake is complete, as defined Section 4.1.1 of [QUIC-TLS].
 *
 * A client MUST NOT send 0-RTT packets once it starts processing 1-RTT
 * packets from the server.  This means that 0-RTT packets cannot
 * contain any response to frames from 1-RTT packets.  For instance, a
 * client cannot send an ACK frame in a 0-RTT packet, because that can
 * only acknowledge a 1-RTT packet.  An acknowledgment for a 1-RTT
 * packet MUST be carried in a 1-RTT packet.
 *
 * A server SHOULD treat a violation of remembered limits
 * (Section 7.4.1) as a connection error of an appropriate type (for
 * instance, a FLOW_CONTROL_ERROR for exceeding stream data limits).
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.3">QUIC Spec/Section 17.2.3</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
@ToString( callSuper = true )
@RequiredArgsConstructor
public class ZeroRttPacketImpl extends BaseLongHeaderPacket implements NumberedPacket, FrameContainingPacket {

    private final @NonNull List<Frame> payload = new LinkedList<>();
    // private VariableLengthInteger length; // that is the #getPayloadLength()
    private PacketNumber packetNumber;

    @Override
    public boolean isPacketValid() {
        return ( ( flags & 0b10000000 ) == 0b10000000 )
                && ( ( flags & 0b01000000 ) == 0b01000000 )
                && ( ( flags & 0b00110000 ) == 0b00010000 ) // LongHeaderPacketType.ZERO_RTT
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
        long sum = getHeaderLength();
        VariableLengthInteger payloadLength = getPayloadLength();
        sum += payloadLength.getEncodedLengthInBytes();
        sum += payloadLength.getValue();
        return sum;
    }

    @Override
    public long getHeaderLength() {
        return super.getHeaderLength()
                + getPacketNumberLength();
    }
}

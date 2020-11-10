package com.timtrense.quic.impl.packets;

import java.util.List;
import lombok.Data;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameContainingPacket;
import com.timtrense.quic.LongHeaderPacket;
import com.timtrense.quic.NumberedPacket;
import com.timtrense.quic.PacketNumber;
import com.timtrense.quic.ProtocolVersion;
import com.timtrense.quic.VariableLengthInteger;

/**
 * An Initial packet uses long headers with a type value of 0x0.  It
 * carries the first CRYPTO frames sent by the client and server to
 * perform key exchange, and carries ACKs in either direction.
 *
 * The Initial packet contains a long header as well as the Length and
 * Packet Number fields; see Section 17.2.  The first byte contains the
 * Reserved and Packet Number Length bits; see also Section 17.2.
 * Between the Source Connection ID and Length fields, there are two
 * additional fields specific to the Initial packet.
 *
 * In order to prevent tampering by version-unaware middleboxes, Initial
 * packets are protected with connection- and version-specific keys
 * (Initial keys) as described in [QUIC-TLS].  This protection does not
 * provide confidentiality or integrity against on-path attackers, but
 * provides some level of protection against off-path attackers.
 *
 * The client and server use the Initial packet type for any packet that
 * contains an initial cryptographic handshake message. This includes
 * all cases where a new packet containing the initial cryptographic
 * message needs to be created, such as the packets sent after receiving
 * a Retry packet (Section 17.2.5).
 *
 * A server sends its first Initial packet in response to a client
 * Initial. A server may send multiple Initial packets. The
 * cryptographic key exchange could require multiple round trips or
 * retransmissions of this data.
 *
 * The payload of an Initial packet includes a CRYPTO frame (or frames)
 * containing a cryptographic handshake message, ACK frames, or both.
 * PING, PADDING, and CONNECTION_CLOSE frames of type 0x1c are also
 * permitted. An endpoint that receives an Initial packet containing
 * other frames can either discard the packet as spurious or treat it as
 * a connection error.
 *
 * The first packet sent by a client always includes a CRYPTO frame that
 * contains the start or all of the first cryptographic handshake
 * message. The first CRYPTO frame sent always begins at an offset of
 * 0; see Section 7.
 *
 * Note that if the server sends a HelloRetryRequest, the client will
 * send another series of Initial packets.  These Initial packets will
 * continue the cryptographic handshake and will contain CRYPTO frames
 * starting at an offset matching the size of the CRYPTO frames sent in
 * the first flight of Initial packets.
 *
 * <p/>
 * <h2>Abandoning Initial Packets</h2>
 * A client stops both sending and processing Initial packets when it
 * sends its first Handshake packet.  A server stops sending and
 * processing Initial packets when it receives its first Handshake
 * packet.  Though packets might still be in flight or awaiting
 * acknowledgment, no further Initial packets need to be exchanged
 * beyond this point.  Initial packet protection keys are discarded (see
 * Section 4.9.1 of [QUIC-TLS]) along with any loss recovery and
 * congestion control state; see Section 6.4 of [QUIC-RECOVERY].
 *
 * Any data in CRYPTO frames is discarded - and no longer retransmitted
 * - when Initial keys are discarded.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.2">QUIC Spec/Section 17.2.2</a>
 */
@Data
public class InitialPacketImpl implements LongHeaderPacket, NumberedPacket, FrameContainingPacket {

    private byte flags;
    private ProtocolVersion version;
    private long destinationConnectionIdLength;
    private ConnectionId destinationConnectionId;
    private long sourceConnectionIdLength;
    private ConnectionId sourceConnectionId;
    private VariableLengthInteger tokenLength;
    private byte[] token;
    // private VariableLengthInteger length; // that is the #getPayloadLength()
    private PacketNumber packetNumber;
    private List<Frame> payload;

    @Override
    public boolean isPacketValid() {
        return ( ( flags & 0b10000000 ) == 0b10000000 )
                && ( ( flags & 0b01000000 ) == 0b01000000 )
                && ( ( flags & 0b00110000 ) == 0b00000000 ) // LongHeaderPacketType.INITIAL
                && ( ( flags & 0b00000011 ) != 0b00000000 )
                && ( version != null )
                && ( version != ProtocolVersion.RESERVED_FOR_VERSION_NEGOTIATION )
                && tokenLength != null
                &&
                (
                        tokenLength.longValue() == 0
                                ? token == null
                                : ( token != null && token.length == tokenLength.longValue() )
                )
                && packetNumber != null;
    }

    @Override
    public int getPacketNumberLength() {
        // "pn_length = (packet[0] & 0x03) + 1" QUIC Spec-TLS/Section 5.4.1
        return ( flags & 0b00000011 ) + 1;
    }

    @Override
    public long getPacketLength() {
        // this sum will be precomputed by the compiler
        long sum = 1 // flags
                + 4 // version-length
                + 1 // destination connection id length field
                + 1 // source connection id length field
                ;
        sum += destinationConnectionIdLength;
        sum += sourceConnectionIdLength;
        sum += tokenLength.getEncodedLengthInBytes();
        sum += tokenLength.getValue();
        sum += getPacketNumberLength();
        VariableLengthInteger payloadLength = getPayloadLength();
        sum += payloadLength.getEncodedLengthInBytes();
        sum += payloadLength.getValue();
        return sum;
    }
}

package com.timtrense.quic.impl.packets;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.LongHeaderPacket;
import com.timtrense.quic.ProtocolVersion;

/**
 * A Retry packet uses a long packet header with a type value of 0x3.
 * It carries an address validation token created by the server.  It is
 * used by a server that wishes to perform a retry; see Section 8.1.
 *
 * A Retry packet (shown in Figure 18) does not contain any protected
 * fields.  The value in the Unused field is set to an arbitrary value
 * by the server; a client MUST ignore these bits.  In addition to the
 * fields from the long header, it contains these additional fields:
 *
 * Retry Token:  An opaque token that the server can use to validate the
 * client's address.
 *
 * Retry Integrity Tag:  See the Retry Packet Integrity section of
 * [QUIC-TLS].
 *
 * <p/>
 * <h2>Sending a Retry Packet</h2>
 * The server populates the Destination Connection ID with the
 * connection ID that the client included in the Source Connection ID of
 * the Initial packet.
 *
 * The server includes a connection ID of its choice in the Source
 * Connection ID field.  This value MUST NOT be equal to the Destination
 * Connection ID field of the packet sent by the client.  A client MUST
 * discard a Retry packet that contains a Source Connection ID field
 * that is identical to the Destination Connection ID field of its
 * Initial packet.  The client MUST use the value from the Source
 * Connection ID field of the Retry packet in the Destination Connection
 * ID field of subsequent packets that it sends.
 *
 * A server MAY send Retry packets in response to Initial and 0-RTT
 * packets.  A server can either discard or buffer 0-RTT packets that it
 * receives.  A server can send multiple Retry packets as it receives
 * Initial or 0-RTT packets.  A server MUST NOT send more than one Retry
 * packet in response to a single UDP datagram.
 *
 * <p/>
 * <h2>Handling a Retry Packet</h2>
 * A client MUST accept and process at most one Retry packet for each
 * connection attempt.  After the client has received and processed an
 * Initial or Retry packet from the server, it MUST discard any
 * subsequent Retry packets that it receives.
 *
 * Clients MUST discard Retry packets that have a Retry Integrity Tag
 * that cannot be validated; see the Retry Packet Integrity section of
 * [QUIC-TLS].  This diminishes an off-path attacker's ability to inject
 * a Retry packet and protects against accidental corruption of Retry
 * packets.  A client MUST discard a Retry packet with a zero-length
 * Retry Token field.
 *
 * The client responds to a Retry packet with an Initial packet that
 * includes the provided Retry Token to continue connection
 * establishment.
 *
 * A client sets the Destination Connection ID field of this Initial
 * packet to the value from the Source Connection ID in the Retry
 * packet.  Changing Destination Connection ID also results in a change
 * to the keys used to protect the Initial packet.  It also sets the
 * Token field to the token provided in the Retry.  The client MUST NOT
 * change the Source Connection ID because the server could include the
 * connection ID as part of its token validation logic; see
 * Section 8.1.4.
 *
 * A Retry packet does not include a packet number and cannot be
 * explicitly acknowledged by a client.
 *
 * <p/>
 * <h2>Continuing a Handshake after Retry</h2>
 * Subsequent Initial packets from the client include the connection ID
 * and token values from the Retry packet.  The client copies the Source
 * Connection ID field from the Retry packet to the Destination
 * Connection ID field and uses this value until an Initial packet with
 * an updated value is received; see Section 7.2.  The value of the
 * Token field is copied to all subsequent Initial packets; see
 * Section 8.1.2.
 *
 * Other than updating the Destination Connection ID and Token fields,
 * the Initial packet sent by the client is subject to the same
 * restrictions as the first Initial packet.  A client MUST use the same
 * cryptographic handshake message it included in this packet.  A server
 * MAY treat a packet that contains a different cryptographic handshake
 * message as a connection error or discard it.
 *
 * A client MAY attempt 0-RTT after receiving a Retry packet by sending
 * 0-RTT packets to the connection ID provided by the server.  A client
 * MUST NOT change the cryptographic handshake message it sends in
 * response to receiving a Retry.
 *
 * A client MUST NOT reset the packet number for any packet number space
 * after processing a Retry packet.  In particular, 0-RTT packets
 * contain confidential information that will most likely be
 * retransmitted on receiving a Retry packet.  The keys used to protect
 * these new 0-RTT packets will not change as a result of responding to
 * a Retry packet.  However, the data sent in these packets could be
 * different than what was sent earlier.  Sending these new packets with
 * the same packet number is likely to compromise the packet protection
 * for those packets because the same key and nonce could be used to
 * protect different content.  A server MAY abort the connection if it
 * detects that the client reset the packet number.
 *
 * The connection IDs used on Initial and Retry packets exchanged
 * between client and server are copied to the transport parameters and
 * validated as described in Section 7.3.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2.5">QUIC Spec/Section 17.2.5</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
@RequiredArgsConstructor
public class RetryPacketImpl extends BaseLongHeaderPacket {

    private byte[] retryToken; // length = (end of datagram - 16 bytes for retryIntegrityTag) - (length of other fields)
    private byte[] retryIntegrityTag; // length 16 bytes

    @Override
    public boolean isPacketValid() {
        return ( ( flags & 0b10000000 ) == 0b10000000 )
                && ( ( flags & 0b01000000 ) == 0b01000000 )
                && ( ( flags & 0b00110000 ) == 0b00110000 ) // LongHeaderPacketType.RETRY
                // && ( ( flags & 0b00001111 ) == <ARBITRARY AND TO BE IGNORED> )
                && ( version != null )
                && ( version != ProtocolVersion.RESERVED_FOR_VERSION_NEGOTIATION )
                && retryToken != null
                && retryToken.length != 0
                && retryIntegrityTag != null
                && retryIntegrityTag.length == 16;
    }

    @Override
    public long getPacketLength() {
        return super.getPacketLength()
                + retryToken.length
                + 16L // retry integrity tag length
                ;
    }
}

package com.timtrense.quic.impl;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EncryptionLevel;
import com.timtrense.quic.EndpointRole;

/**
 * The context in which parsing happens.
 * The context holds all values that are required for parsing, yet not contained in
 * the {@link java.net.DatagramPacket datagrams} nor {@link com.timtrense.quic.Packet packets} to be parsed
 *
 * @author Tim Trense
 */
public interface ParsingContext {

    /**
     * indicates whether parsing is done on server or client side
     *
     * @return the role of the endpoint on which parsing is done
     */
    EndpointRole getRole();

    /**
     * Searches the relevant keys for encrypting or decrypting messages for that connection at
     * the given encryption level.
     * <p>
     * Note: The implementation may return null if the requested keying material is not yet present
     * or exchanged with the peer.
     * <p>
     * Note: Implementations must provide an initialized instance.
     *
     * @param connectionId    the resolved connection id
     * @param encryptionLevel the level to retrieve the keys from
     * @return the associated protection
     */
    PacketProtection getPacketProtection( ConnectionId connectionId, EncryptionLevel encryptionLevel );

    //TODO: getPeerSecret(byte[] connectionId, EncryptionLevel)
    //TODO: getLocalSecret(byte[] connectionId, EncryptionLevel)
    //TODO: getConnectionIdLength(byte[] connectionId)
    //TODO: getConnectionProtocolInUse(byte[] connectionId)
    //TODO: setConnectionProtocolInUse(byte[] connectionId, ProtocolVersion isUse)
    //TODO: setConnectionIdLength(byte[] connectionId, int connectionIdLength)
}

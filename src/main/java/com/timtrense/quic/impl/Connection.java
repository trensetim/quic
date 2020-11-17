package com.timtrense.quic.impl;

import java.util.Set;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EncryptionLevel;

/**
 * Basic abstraction of a QUIC connection
 *
 * @author Tim Trense
 */
public interface Connection {

    /**
     * Each QUIC connection is identified by a set of both local and remote {@link ConnectionId connection IDs}.
     * The local IDs are stored by the owner of this instance while the remote IDs can be controlled by the peer,
     * thus making them part of this connection.
     *
     * @return all known connection IDs from the remote peer
     */
    Set<ConnectionId> getRemoteConnectionIds();

    /**
     * QUIC packets use different levels of protection.
     * If already known, the user may request the protection at a specific level.
     * Note that by progressing in the crypto handshake (and even before any communication in this session),
     * the known protections may vary depending on the information and state already present on this endpoint.
     *
     * @param encryptionLevel the protection level, not null
     * @return the protection, if already known
     */
    PacketProtection getPacketProtection( EncryptionLevel encryptionLevel );

}

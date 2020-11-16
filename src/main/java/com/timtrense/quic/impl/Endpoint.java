package com.timtrense.quic.impl;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EncryptionLevel;
import com.timtrense.quic.EndpointRole;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

/**
 * An endpoint is the most high level access for an application to use QUIC.
 *
 * @author Tim Trense
 */
@Data
@RequiredArgsConstructor
public class Endpoint implements ParsingContext {

    private @NonNull EndpointRole role;
    /**
     * all configuration parameters of this endpoint
     */
    private @NonNull EndpointConfiguration configuration = new EndpointConfiguration();
    /**
     * Maps local {@link ConnectionId connection IDs} to the connection
     */
    private @NonNull Map<ConnectionId, Connection> connections = new HashMap<>();

    /**
     * Searches the connection from one of the given local connection ids
     *
     * @param connectionId a local connection id
     * @return the connection if found
     */
    Connection findConnectionByLocalId(@NonNull ConnectionId connectionId) {
        for (Map.Entry<ConnectionId, Connection> entries : connections.entrySet()) {
            if (entries.getKey().equals(connectionId)) {
                return entries.getValue();
            }
        }
        return null;
    }

    /**
     * Searches the connection from one of the given local connection ids
     *
     * @param connectionId the serialized form of a local connection id
     * @return the connection if found
     */
    Connection findConnectionByLocalId(@NonNull byte[] connectionId) {
        for (Map.Entry<ConnectionId, Connection> entries : connections.entrySet()) {
            if (entries.getKey().equalsValue(connectionId)) {
                return entries.getValue();
            }
        }
        return null;
    }

    @Override
    public PacketProtection getPacketProtection(ConnectionId connectionId, EncryptionLevel encryptionLevel) {
        Connection connection = findConnectionByLocalId(connectionId);
        if (connection == null) {
            return null;
        }
        return connection.getPacketProtection(encryptionLevel);
    }

    /**
     * @return a yet-unused 8 byte length connection id in serialized form
     */
    public byte[] createRandomUnusedConnectionId() {
        byte[] cid = new byte[8];
        do {
            configuration.getRandom().nextBytes(cid);
            // this loop will not repeat in real life, because chances of
            // having a colliding 256-pow-8 random value are near to zero
        } while (findConnectionByLocalId(cid) != null);
        return cid;
    }
}

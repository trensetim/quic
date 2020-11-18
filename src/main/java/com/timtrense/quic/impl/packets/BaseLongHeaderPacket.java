package com.timtrense.quic.impl.packets;

import lombok.Data;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.LongHeaderPacket;
import com.timtrense.quic.ProtocolVersion;

/**
 * Common abstract base class for all {@link LongHeaderPacket long header packets},
 * containing all properties that they all share.
 *
 * @author Tim Trense
 */
@Data
public abstract class BaseLongHeaderPacket implements LongHeaderPacket {

    protected byte flags;
    protected ProtocolVersion version;
    protected long destinationConnectionIdLength;
    protected ConnectionId destinationConnectionId;
    protected long sourceConnectionIdLength;
    protected ConnectionId sourceConnectionId;

    /**
     * Subclasses still need to override this. This implementation may not give the complete length
     *
     * @return the length of the base part of the long header packet
     */
    @Override
    public long getPacketLength() {
        return getHeaderLength();
    }

    /**
     * Subclasses still need to override this. This implementation may not give the complete length
     *
     * @return the length of the base part of the long header packet
     */
    @Override
    public long getHeaderLength() {
        // this sum will be precomputed by the compiler
        long sum = 1L // flags
                + 4L // version-length
                + 1L // destination connection id length field
                + 1L // source connection id length field
                ;
        sum += destinationConnectionIdLength;
        sum += sourceConnectionIdLength;
        return sum;
    }
}

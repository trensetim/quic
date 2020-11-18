package com.timtrense.quic.impl.exception;

import java.nio.ByteBuffer;
import lombok.Getter;
import lombok.NonNull;

import com.timtrense.quic.Packet;

/**
 * The frames header or content is no valid QUIC frame
 *
 * @author Tim Trense
 */
public class MalformedFrameException extends QuicParsingException {

    @Getter
    private final Packet containingPacket;
    @Getter
    private final @NonNull ByteBuffer payload;
    /**
     * the index of the packet within the datagram
     */
    @Getter
    private final int frameIndex;

    public MalformedFrameException(
            Packet containingPacket,
            @NonNull ByteBuffer payload,
            int frameIndex
    ) {
        super( "The frames content is not valid: Frame number " + frameIndex );
        this.containingPacket = containingPacket;
        this.payload = payload;
        this.frameIndex = frameIndex;
    }

    public MalformedFrameException(
            String message,
            Packet containingPacket,
            @NonNull ByteBuffer payload,
            int frameIndex
    ) {
        super( message );
        this.containingPacket = containingPacket;
        this.payload = payload;
        this.frameIndex = frameIndex;
    }
}

package com.timtrense.quic.impl.exception;

import java.nio.ByteBuffer;

import lombok.Getter;
import lombok.NonNull;

import com.timtrense.quic.impl.ReceivedDatagram;

/**
 * The datagrams content is no valid QUIC datagram payload
 *
 * @author Tim Trense
 */
public class MalformedPacketException extends QuicParsingException {

    @Getter
    private final ReceivedDatagram datagram;
    @Getter
    private final @NonNull ByteBuffer payload;
    /**
     * the index of the packet within the datagram
     */
    @Getter
    private final int packetIndex;

    public MalformedPacketException(
            ReceivedDatagram datagram,
            @NonNull ByteBuffer payload,
            int packetIndex
    ) {
        super( "The packets content is not valid: Packet number " + packetIndex );
        this.datagram = datagram;
        this.payload = payload;
        this.packetIndex = packetIndex;
    }

    public MalformedPacketException(
            String message,
            ReceivedDatagram datagram,
            @NonNull ByteBuffer payload,
            int packetIndex
    ) {
        super( message );
        this.datagram = datagram;
        this.payload = payload;
        this.packetIndex = packetIndex;
    }
}

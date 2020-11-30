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
public class MalformedDatagramException extends QuicParsingException {

    @Getter
    private final transient @NonNull ReceivedDatagram datagram;
    @Getter
    private final transient @NonNull ByteBuffer payload;

    public MalformedDatagramException(
            @NonNull ReceivedDatagram datagram,
            @NonNull ByteBuffer payload
    ) {
        super( "The datagrams content is not valid for a QUIC datagram" );
        this.datagram = datagram;
        this.payload = payload;
    }
}

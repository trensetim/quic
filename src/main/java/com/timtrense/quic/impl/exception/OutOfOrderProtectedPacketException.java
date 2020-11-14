package com.timtrense.quic.impl.exception;

import java.nio.ByteBuffer;

import lombok.Getter;
import lombok.NonNull;

import com.timtrense.quic.impl.ReceivedDatagram;

/**
 * At least one packet of the datagrams content could not be parsed,
 * because the required decryption material was missing.
 * <p>
 * Could happen when, due to packet reordering, the first short header packet arrives before handshake is finished.
 * https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.7
 * "Due to reordering and loss, protected packets might be received by an
 * endpoint before the final TLS handshake messages are received."
 *
 * @author Tim Trense
 */
public class OutOfOrderProtectedPacketException extends QuicParsingException {

    @Getter
    private final ReceivedDatagram datagram;
    @Getter
    private final @NonNull ByteBuffer payload;
    /**
     * the index of the packet within the datagram
     */
    @Getter
    private final int packetIndex;

    public OutOfOrderProtectedPacketException(
            ReceivedDatagram datagram,
            @NonNull ByteBuffer payload,
            int packetIndex
    ) {
        super( "The packet was received out-of-order and may be processed later: Packet number " + packetIndex );
        this.datagram = datagram;
        this.payload = payload;
        this.packetIndex = packetIndex;
    }

    public OutOfOrderProtectedPacketException(
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

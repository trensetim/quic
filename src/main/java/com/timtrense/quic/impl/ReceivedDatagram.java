package com.timtrense.quic.impl;

import java.net.DatagramPacket;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * A {@link DatagramPacket} that was received by a {@link Receiver}
 *
 * @author Tim Trense
 */
@Data
@RequiredArgsConstructor
@AllArgsConstructor
public class ReceivedDatagram {

    /**
     * the actual received datagram
     */
    private @NonNull DatagramPacket datagram;
    /**
     * the timestamp of receiving
     */
    private @NonNull Instant receiveTime;
    /**
     * a counter given by the {@link Receiver}
     */
    private long number;
    /**
     * how many times the datagram could not be parsed,
     * possibly due to the lack of decryption material because of reordering on the network
     */
    private short parseRetryCount = 0;
}

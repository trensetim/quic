package com.timtrense.quic.impl;

import java.nio.ByteBuffer;

import com.timtrense.quic.Packet;
import com.timtrense.quic.impl.exception.QuicParsingException;

/**
 * Parsing algorithm for coalesced packets within a datagram
 *
 * @author Tim Trense
 */
public interface PacketParser {

    /**
     * Parses the data of the received datagram using the remainingData starting from the buffers current position.
     * Implementations do not need to leave the buffer untouched if a parsing error occurs.
     * Implementations MUST position the buffer after the last byte of the parsed packet on successful exit.
     *
     * @param receivedDatagram the received datagram
     * @param remainingData    a buffer on the received datagrams data, positioned
     *                         at the start byte of the packet with No.=packetIndex to be parsed
     * @param packetIndex      the index of the packet to be parsed within the datagram
     * @return the parsed packet. never an invalid one nor null
     * @throws QuicParsingException if any parsing error occurs
     */
    Packet parsePacket(
            ReceivedDatagram receivedDatagram,
            ByteBuffer remainingData,
            int packetIndex
    ) throws QuicParsingException;

    /**
     * @return the frame parser in charge
     */
    FrameParser getFrameParser();
}

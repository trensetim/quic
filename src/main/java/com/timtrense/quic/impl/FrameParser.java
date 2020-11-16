package com.timtrense.quic.impl;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.Packet;
import com.timtrense.quic.impl.exception.QuicParsingException;

/**
 * Parsing algorithm for frames within a packet
 *
 * @author Tim Trense
 */
public interface FrameParser {

    /**
     * Parses one frame in the given packet.
     *
     * @param containingPacket the packet containing those frames
     * @param data             the data of the datagram, positioned at the start of this next frame
     * @param maxLength        the remaining length of the packet, that this next frame could take at most
     * @return a parsed, valid frame
     * @throws QuicParsingException if any parsing error occurs
     */
    Frame parseFrame(
            @NonNull Packet containingPacket,
            @NonNull ByteBuffer data,
            int frameIndex,
            int maxLength )
            throws QuicParsingException;

    /**
     * Parses all frames in the given packet.
     *
     * @param containingPacket the packet that will contain those frames
     * @param data             the data of the datagram, positioned at the start of the containing packet
     * @param packetLength     the length of the packet, or -1 if the packet takes up all
     *                         data till the end of the datagram
     * @return all frames contained in that packet, never an incomplete or invalid list
     * @throws QuicParsingException if any parsing error occurs
     */
    default List<Frame> parseFrames(
            @NonNull Packet containingPacket,
            @NonNull ByteBuffer data,
            int packetLength )
            throws QuicParsingException {
        if ( packetLength < 0 ) {
            packetLength = data.remaining();
        }
        List<Frame> payload = new LinkedList<>();
        for ( int packetIndex = 0; packetLength > 0; packetIndex++ ) {
            Frame f = parseFrame( containingPacket, data, packetIndex, packetLength );
            if ( f == null ) {
                payload = null;
                break;
            }
            payload.add( f );
            packetLength -= f.getFrameLength();
        }
        return payload;
    }
}

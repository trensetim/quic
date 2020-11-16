package com.timtrense.quic.impl;

import java.nio.ByteBuffer;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.Packet;
import com.timtrense.quic.impl.exception.QuicParsingException;

/**
 * Parsing algorithm for frames within a packet
 *
 * @author Tim Trense
 */
@Data
public class FrameParserImpl implements FrameParser {

    private @NonNull ParsingContext context;

    @Override
    public Frame parseFrame(
            @NonNull Packet containingPacket,
            @NonNull ByteBuffer data,
            int frameIndex,
            int maxLength)
            throws QuicParsingException {
        return null; //TODO implement
    }

}

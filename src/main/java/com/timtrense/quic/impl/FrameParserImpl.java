package com.timtrense.quic.impl;

import java.nio.ByteBuffer;
import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.Packet;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import com.timtrense.quic.impl.exception.MalformedFrameException;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.impl.frames.CryptoFrameImpl;
import com.timtrense.quic.impl.frames.MultiPaddingFrameImpl;

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
            int maxLength )
            throws QuicParsingException {
        long frameTypeRaw = VariableLengthIntegerEncoder.decode( data );
        FrameType frameType = FrameType.findByValue( (int)frameTypeRaw );
        if ( frameType == null ) {
            throw new MalformedFrameException( "Unknown Frame Type: " + frameTypeRaw,
                    containingPacket, data, frameIndex );
        }

        maxLength -= frameType.getValue().getEncodedLengthInBytes(); // because we just parsed a varint

        Frame result;
        switch ( frameType.getGeneralType() ) {
            case PADDING:
                // we just detected the start of AT LEAST one padding frame.
                // lets try finding more consecutive paddings to reduce
                // amount of instantiated padding frame objects
                result = parseMultiPaddingFrame( data, maxLength );
                break;
            case CRYPTO:
                result = new CryptoFrameImpl( frameType );
                parseFrame( (CryptoFrameImpl)result, containingPacket, data, frameIndex, maxLength );
                break;
            //TODO implement remaining frame types
            default:
                throw new MalformedFrameException( "Unimplemented Frame Type: " + frameType,
                        containingPacket, data, frameIndex );
        }
        return result;
    }

    private Frame parseMultiPaddingFrame( ByteBuffer data, int maxLength ) {
        byte[] rawData = data.array();
        int offset = data.position();
        int paddingCount;
        for ( paddingCount = 0; paddingCount < maxLength; paddingCount++ ) {
            if ( rawData[offset + paddingCount] != FrameType.PADDING.getLongValue() ) {
                break;
            }
        }
        paddingCount++; // because already one Padding Frame was parsed by top parseFrame()
        return new MultiPaddingFrameImpl( paddingCount );
    }

    private void parseFrame( CryptoFrameImpl frame, Packet containingPacket,
            ByteBuffer data, int frameIndex, int maxLength ) throws QuicParsingException {
        long offset = VariableLengthIntegerEncoder.decode( data );
        long length = VariableLengthIntegerEncoder.decode( data );

        /*
       "There is a separate flow of cryptographic handshake data in each
       encryption level, each of which starts at an offset of 0.  This
       implies that each encryption level is treated as a separate CRYPTO
       stream of data.

       The largest offset delivered on a stream - the sum of the offset and
       data length - cannot exceed 2^62-1.  Receipt of a frame that exceeds
       this limit MUST be treated as a connection error of type
       FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED."
       Quote from https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.6
         */
        if ( offset < 0 ) {
            throw new MalformedFrameException( "CRYPTO offset exceeds limits: " + offset,
                    containingPacket, data, frameIndex );
        }
        if ( offset + length > VariableLengthIntegerEncoder.MAX_VALUE ) {
            throw new MalformedFrameException( "CRYPTO offset at frames end exceeds limits:" +
                    " offset=" + offset +
                    ", length=" + length,
                    containingPacket, data, frameIndex );
        }

        // BTW: we do not expect to get more than Integer.MAX_VALUE -1 bytes anyways, because that would
        // not fit into any datagrams MTU on any reasonable network

        if ( length > maxLength ) {
            throw new MalformedFrameException( "CRYPTO frames length states more bytes than contained in the packet:" +
                    " length=" + length +
                    ", maxLength=" + maxLength,
                    containingPacket, data, frameIndex );
        }
        byte[] cryptoData = new byte[(int)length];
        data.get( cryptoData );
        frame.setOffset( new VariableLengthInteger( offset ) );
        frame.setLength( new VariableLengthInteger( length ) );
        frame.setCryptoData( cryptoData );
    }


}

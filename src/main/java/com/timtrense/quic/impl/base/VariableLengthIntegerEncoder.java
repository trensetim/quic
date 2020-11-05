package com.timtrense.quic.impl.base;

import java.nio.ByteBuffer;

/**
 * Utility class to encode and decode unsigned long integer values within the interval [ 0 ; 2^62-1 ] .
 *
 * This encoding/decoding relies on the fact that java uses big endian byte order.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16">QUIC Spec/Section 16</a>
 */
public class VariableLengthIntegerEncoder {

    /**
     * determines the required number of bytes to encode the given value.
     *
     * @param value the non-negative value to encode
     * @return the number of bytes required to encode the value or 0 if the value is out-of-bounds
     */
    public static byte getLengthInBytes( long value ) {
        if ( value < 0 ) {
            return 0;
        }
        else if ( value <= 63L ) {
            return 1;
        }
        else if ( value <= 16383L ) {
            return 2;
        }
        else if ( value <= 1073741823L ) {
            return 4;
        }
        else if ( value <= 4611686018427387903L ) {
            return 8;
        }
        else {
            return 0;
        }
    }

    /**
     * encodes the given value. on error: leaves the buffer as it was before invocation.
     * on success the returned number of bytes were added to the buffer.
     *
     * the function is not thread-safe unless synchronized on the parameter.
     *
     * @param value  the non-negative long integer to encode
     * @param buffer the target to append the encoded bytes
     * @return the number of bytes added (1, 2, 4 or 8) or 0 if the value was out of bounds
     */
    public static int encode( long value, ByteBuffer buffer ) {
        if ( value < 0 ) {
            return 0;
        }
        else if ( value <= 63 ) {
            buffer.put( (byte)value );
            return 1;
        }
        else if ( value <= 16383L ) {
            buffer.put( (byte)( ( value / 256 ) | 0x40 ) );
            buffer.put( (byte)( value % 256 ) );
            return 2;
        }
        else if ( value <= 1073741823L ) {
            int initialPosition = buffer.position();
            buffer.putInt( (int)value );
            buffer.put( initialPosition, (byte)( buffer.get( initialPosition ) | (byte)0x80 ) );
            return 4;
        }
        else if ( value <= 4611686018427387903L ) {
            int initialPosition = buffer.position();
            buffer.putLong( value );
            buffer.put( initialPosition, (byte)( buffer.get( initialPosition ) | (byte)0xc0 ) );
            return 8;
        }
        else {
            return 0;
        }
    }

    /**
     * decodes a value from the given source. on error: leaves the buffer as it was before invocation.
     * on success the required number of bytes were read from the buffer. the number of bytes read can
     * be computed by comparing the buffers position before and after the invocation.
     *
     * the function is not thread-safe unless synchronized on the parameter.
     *
     * @param buffer the source to decode from
     * @return the decoded non-negative value or -1 on failure
     */
    public static long decode( ByteBuffer buffer ) {
        if ( !buffer.hasRemaining() ) {
            return -1;
        }

        int remaining = buffer.remaining();
        byte firstLengthByte = buffer.get();
        buffer.position( buffer.position() - 1 );

        int lengthType = ( firstLengthByte & 0xc0 ) >> 6;
        if ( lengthType == 0 ) {
            return firstLengthByte & 0b00111111L;
        }
        else if ( lengthType == 1 && remaining > 1 ) {
            return buffer.getShort() & 0x3fffL;
        }
        else if ( lengthType == 2 && remaining > 3 ) {
            return buffer.getInt() & 0x3fffffffL;
        }
        else if ( lengthType == 3 && remaining > 7 ) {
            return buffer.getLong() & 0x3fffffffffffffffL;
        }
        else {
            return -1;
        }
    }

    /**
     * decodes a classic java integer (or long) from the given bytes.
     *
     * @param data the binary representation
     * @param off  the offset in the array
     * @param len  the length to parse (for an int not more than 4 (or 8 for long), otherwise arithmetic interesting things will happen)
     * @return the decoded integer value as a long
     */
    public static long decodeFixedLengthInteger( byte[] data, int off, int len ) {
        long value = 0;
        for ( int i = 0; i < len; i++ ) {
            value = ( value << 8 ) | ( data[i + off] & 0xff );
        }
        return value;
    }
}

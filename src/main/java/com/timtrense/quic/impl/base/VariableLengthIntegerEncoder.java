package com.timtrense.quic.impl.base;

import java.nio.ByteBuffer;

import com.timtrense.quic.VariableLengthInteger;

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
     * The largest number that can be encoded as a {@link VariableLengthInteger}.
     * Equal to 2 pow 62 minus 1.
     */
    public static final long MAX_VALUE = 4611686018427387903L;

    /**
     * The largest number that can be encoded as a {@link VariableLengthInteger} using one byte.
     * Equal to 2 pow 6 minus 1.
     */
    public static final long MAX_VALUE_1_BYTE = 63L;

    /**
     * The largest number that can be encoded as a {@link VariableLengthInteger} using two bytes.
     * Equal to 2 pow 14 minus 1.
     */
    public static final long MAX_VALUE_2_BYTE = 16383L;

    /**
     * The largest number that can be encoded as a {@link VariableLengthInteger} using four bytes.
     * Equal to 2 pow 30 minus 1.
     */
    public static final long MAX_VALUE_4_BYTE = 1073741823L;

    /**
     * The largest number that can be encoded as a {@link VariableLengthInteger} using eight bytes.
     * Equal to 2 pow 62 minus 1 thus equal to {@link #MAX_VALUE}
     */
    public static final long MAX_VALUE_8_BYTE = MAX_VALUE;

    /**
     * The smallest number that can be encoded as a {@link VariableLengthInteger}.
     * Equal to zero, because var-ints are by definition non-negative.
     */
    public static final long MIN_VALUE = 0L;

    /**
     * The bit-mask to apply to one unsigned byte to get the encoded var-int value
     * (if that byte encodes a single-byte var-int)
     */
    public static final long MASK_1_BYTE = 0b00111111L;

    /**
     * The bit-mask to apply to two consecutive unsigned bytes (aka an unsigned short) to get the encoded var-int value
     * (if that bytes encode a two-byte var-int)
     */
    public static final long MASK_2_BYTE = 0x3fffL;

    /**
     * The bit-mask to apply to four consecutive unsigned bytes (aka an unsigned short) to get the encoded var-int
     * value (if that bytes encode a four-byte var-int)
     */
    public static final long MASK_4_BYTE = 0x3fffffffL;
    /**
     * The bit-mask to apply to eight consecutive unsigned bytes (aka an unsigned short) to get the encoded var-int
     * value (if that bytes encode an eight-byte var-int)
     */
    public static final long MASK_8_BYTE = 0x3fffffffffffffffL;

    private VariableLengthIntegerEncoder() {}

    /**
     * determines the required number of bytes to encode the given value.
     *
     * @param value the non-negative value to encode
     * @return the number of bytes required to encode the value or 0 if the value is out-of-bounds
     */
    public static byte getLengthInBytes( long value ) {
        if ( value < MIN_VALUE ) {
            return 0;
        }
        else if ( value <= MAX_VALUE_1_BYTE ) {
            return 1;
        }
        else if ( value <= MAX_VALUE_2_BYTE ) {
            return 2;
        }
        else if ( value <= MAX_VALUE_4_BYTE ) {
            return 4;
        }
        else if ( value <= MAX_VALUE ) {
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
        if ( value < MIN_VALUE ) {
            return 0;
        }
        else if ( value <= MAX_VALUE_1_BYTE ) {
            buffer.put( (byte)value );
            return 1;
        }
        else if ( value <= MAX_VALUE_2_BYTE ) {
            // TODO value >> 8 == value / 256
            buffer.put( (byte)( ( value / 256 ) | 0x40 ) );
            // TODO (byte)value == value % 256
            buffer.put( (byte)( value % 256 ) );
            return 2;
        }
        else if ( value <= MAX_VALUE_4_BYTE ) {
            int initialPosition = buffer.position();
            buffer.putInt( (int)value );
            buffer.put( initialPosition, (byte)( buffer.get( initialPosition ) | (byte)0x80 ) );
            return 4;
        }
        else if ( value <= MAX_VALUE ) {
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
            return buffer.get() & MASK_1_BYTE;
        }
        else if ( lengthType == 1 && remaining > 1 ) {
            return buffer.getShort() & MASK_2_BYTE;
        }
        else if ( lengthType == 2 && remaining > 3 ) {
            return buffer.getInt() & MASK_4_BYTE;
        }
        else if ( lengthType == 3 && remaining > 7 ) {
            return buffer.getLong() & MASK_8_BYTE;
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

    /**
     * decodes a classic java integer (or long) from the given bytes.
     *
     * @param data the binary representation, positioned at the start of the encoded fixed length integer
     * @param len  the length to parse (for an int not more than 4 (or 8 for long), otherwise arithmetic interesting things will happen)
     * @return the decoded integer value as a long
     */
    public static long decodeFixedLengthInteger( ByteBuffer data, int len ) {
        long value = 0;
        for ( int i = 0; i < len; i++ ) {
            int currentByte = data.get() & 0xff;
            value = ( value << 8 ) | ( currentByte & 0xff );
        }
        return value;
    }

    /**
     * encodes a classic java integer (or long) into the given bytes.
     *
     * @param value the actual value to encode
     * @param data  the output for the binary representation
     * @param off   the offset in the array
     * @param len   the length to encode the int in (for an int not more than 4 (or 8 for long), otherwise arithmetic
     *              interesting things will happen)
     */
    public static void encodeFixedLengthInteger( long value, byte[] data, int off, int len ) {
        for ( int i = len - 1; i >= 0; i-- ) {
            data[i + off] = (byte)( value & 0xff );
            value >>= 8;
        }
    }
}

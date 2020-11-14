package com.timtrense.quic;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import java.nio.ByteBuffer;

/**
 * QUIC packets and frames commonly use a variable-length encoding for
 * non-negative integer values.  This encoding ensures that smaller
 * integer values need fewer bytes to encode.
 *
 * The QUIC variable-length integer encoding reserves the two most
 * significant bits of the first byte to encode the base 2 logarithm of
 * the integer encoding length in bytes.  The integer value is encoded
 * on the remaining bits, in network byte order.
 *
 * This means that integers are encoded on 1, 2, 4, or 8 bytes and can
 * encode 6, 14, 30, or 62 bit values respectively.  Table 4 summarizes
 * the encoding properties.
 *
 * <pre>
 *           +------+--------+-------------+-----------------------+
 *           | 2Bit | Length | Usable Bits | Range                 |
 *           +------+--------+-------------+-----------------------+
 *           | 00   | 1      | 6           | 0-63                  |
 *           |      |        |             |                       |
 *           | 01   | 2      | 14          | 0-16383               |
 *           |      |        |             |                       |
 *           | 10   | 4      | 30          | 0-1073741823          |
 *           |      |        |             |                       |
 *           | 11   | 8      | 62          | 0-4611686018427387903 |
 *           +------+--------+-------------+-----------------------+
 * </pre>
 *
 * For example, the eight byte sequence c2 19 7c 5e ff 14 e8 8c (in
 * hexadecimal) decodes to the decimal value 151288809941952652; the
 * four byte sequence 9d 7f 3e 7d decodes to 494878333; the two byte
 * sequence 7b bd decodes to 15293; and the single byte 25 decodes to 37
 * (as does the two byte sequence 40 25).
 *
 * <b>
 * Error codes (Section 20) and versions (Section 15) are described
 * using integers, but do not use this encoding.
 * </b>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16">QUIC Spec/Section 16</a>
 */
@EqualsAndHashCode( callSuper = false, of = "value" )
@Data
public class VariableLengthInteger extends Number
        implements Comparable<VariableLengthInteger> {

    public static VariableLengthInteger ZERO = new VariableLengthInteger( 0L );
    public static VariableLengthInteger ONE = new VariableLengthInteger( 1L );
    public static VariableLengthInteger MIN_VALUE = ZERO;
    public static VariableLengthInteger MAX_VALUE = new VariableLengthInteger( 4611686018427387903L );
    public static VariableLengthInteger MAX_VALUE_1BYTE = new VariableLengthInteger( 63L );
    public static VariableLengthInteger MAX_VALUE_2BYTE = new VariableLengthInteger( 16383L );
    public static VariableLengthInteger MAX_VALUE_4BYTE = new VariableLengthInteger( 1073741823L );
    public static VariableLengthInteger MAX_VALUE_8BYTE = MAX_VALUE;
    public static VariableLengthInteger MIN_VALUE_1BYTE = new VariableLengthInteger( 0L );
    public static VariableLengthInteger MIN_VALUE_2BYTE = new VariableLengthInteger( 64L );
    public static VariableLengthInteger MIN_VALUE_4BYTE = new VariableLengthInteger( 16384L );
    public static VariableLengthInteger MIN_VALUE_8BYTE = new VariableLengthInteger( 1073741824L );

    /**
     * the actual value
     */
    private final long value;
    /**
     * the number of bytes required to encode this value
     */
    private final byte encodedLengthInBytes;

    /**
     * creates a new instance having that value
     *
     * @param value the actual value
     */
    public VariableLengthInteger( long value ) {
        this.value = value;
        this.encodedLengthInBytes = VariableLengthIntegerEncoder.getLengthInBytes( value );
        if ( encodedLengthInBytes == 0 ) {
            throw new IllegalArgumentException( "Cannot encode that value as a VariableLengthInteger: " + value );
        }
    }

    /**
     * creates a new instance having that value
     *
     * @param value                the actual value
     * @param encodedLengthInBytes the number of bytes required to encode this value
     */
    private VariableLengthInteger( long value, byte encodedLengthInBytes ) {
        // private to prevent someone from putting in invalid combinations of those values
        this.value = value;
        this.encodedLengthInBytes = encodedLengthInBytes;
    }

    @Override
    public int intValue() {
        return (int)value;
    }

    @Override
    public long longValue() {
        return value;
    }

    @Override
    public float floatValue() {
        return value;
    }

    @Override
    public double doubleValue() {
        return value;
    }

    @Override
    public int compareTo( @NonNull VariableLengthInteger o ) {
        /*
         * @see Long#compareTo(Long)
         */
        return Long.compare( this.value, o.value );
    }


    /**
     * decodes a value from the given source. leaves the given source as was before invocation if decoding is not
     * possible.
     *
     * this method is not thread-safe unless synchronized on the buffer
     *
     * @param buffer the source to read from
     * @return the decoded value or null if decoding was not possible
     */
    public static VariableLengthInteger decode( @NonNull ByteBuffer buffer ) {
        long value = VariableLengthIntegerEncoder.decode( buffer );
        byte encodedLengthInBytes = VariableLengthIntegerEncoder.getLengthInBytes( value );
        if ( encodedLengthInBytes == 0 ) {
            // out of bounds to encode
            return null;
        }
        else {
            return new VariableLengthInteger( value, encodedLengthInBytes );
        }
    }

    /**
     * encodes this value to the given destination. leaves the given destination as was before invocation if encoding
     * is not possible.
     *
     * this method is not thread-safe unless synchronized on the buffer
     *
     * @param buffer the destination to write to
     * @return the number of bytes added (1, 2, 4 or 8) or 0 if encoding was not possible
     */
    public int encode( @NonNull ByteBuffer buffer ) {
        if ( buffer.position() + encodedLengthInBytes > buffer.limit() ) {
            return 0;
        }
        return VariableLengthIntegerEncoder.encode( value, buffer ); // that would match #encodedLengthInBytes
    }

    /**
     * does not touch this value
     *
     * @return a new instance with its value added by one
     * @throws IllegalArgumentException if this is already the largest possible variable length integer
     */
    public VariableLengthInteger increment() {
        return new VariableLengthInteger( value + 1 );
    }

    /**
     * does not touch this value
     *
     * @param incrementStep the amount to increment by. This value may be zero or negative resulting in no or inverse
     *                      incrementation
     * @return a new instance with its value added by one
     * @throws IllegalArgumentException if this is already the largest possible variable length integer
     */
    public VariableLengthInteger increment( long incrementStep ) {
        return new VariableLengthInteger( value + incrementStep );
    }

    /**
     * does not touch this value
     *
     * @return a new instance with its value reduced by one
     * @throws IllegalArgumentException if this is already the smallest possible variable length integer
     */
    public VariableLengthInteger decrement() {
        return new VariableLengthInteger( value - 1 );
    }

    /**
     * does not touch this value
     *
     * @param decrementStep the amount to increment by. This value may be zero or negative resulting in no or inverse
     *                      incrementation
     * @return a new instance with its value added by one
     * @throws IllegalArgumentException if this is already the largest possible variable length integer
     */
    public VariableLengthInteger decrement( long decrementStep ) {
        return new VariableLengthInteger( value - decrementStep );
    }
}

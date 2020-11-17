package com.timtrense.quic;

import java.nio.ByteBuffer;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VariableLengthIntegerTest {

    @Test
    public void getEncodedLengthInBytes_ofAllByteLengthConstants_isAsClaimedByName() {
        assertEquals( 1, VariableLengthInteger.MIN_VALUE_1BYTE.getEncodedLengthInBytes() );
        assertEquals( 1, VariableLengthInteger.MAX_VALUE_1BYTE.getEncodedLengthInBytes() );

        assertEquals( 2, VariableLengthInteger.MIN_VALUE_2BYTE.getEncodedLengthInBytes() );
        assertEquals( 2, VariableLengthInteger.MAX_VALUE_2BYTE.getEncodedLengthInBytes() );

        assertEquals( 4, VariableLengthInteger.MIN_VALUE_4BYTE.getEncodedLengthInBytes() );
        assertEquals( 4, VariableLengthInteger.MAX_VALUE_4BYTE.getEncodedLengthInBytes() );

        assertEquals( 8, VariableLengthInteger.MAX_VALUE_8BYTE.getEncodedLengthInBytes() );
        assertEquals( 8, VariableLengthInteger.MAX_VALUE_8BYTE.getEncodedLengthInBytes() );
    }

    @Test
    public void getEncodedLengthInBytes_ofMinConstants_is1Byte() {
        assertEquals( 1, VariableLengthInteger.MIN_VALUE_1BYTE.getEncodedLengthInBytes() );
        assertEquals( 1, VariableLengthInteger.MIN_VALUE.getEncodedLengthInBytes() );
        assertEquals( 1, VariableLengthInteger.ZERO.getEncodedLengthInBytes() );
    }

    @Test
    public void getEncodedLengthInBytes_ofMaxConstants_is8Byte() {
        assertEquals( 8, VariableLengthInteger.MAX_VALUE_8BYTE.getEncodedLengthInBytes() );
        assertEquals( 8, VariableLengthInteger.MAX_VALUE.getEncodedLengthInBytes() );
    }

    @Test
    public void encodingAndDecoding_ofAllConstants_remainsValue() {
        VariableLengthInteger[] values = new VariableLengthInteger[]{
                VariableLengthInteger.ZERO,
                VariableLengthInteger.MIN_VALUE,
                VariableLengthInteger.MAX_VALUE,
                VariableLengthInteger.MIN_VALUE_1BYTE,
                VariableLengthInteger.MAX_VALUE_1BYTE,
                VariableLengthInteger.MIN_VALUE_2BYTE,
                VariableLengthInteger.MAX_VALUE_2BYTE,
                VariableLengthInteger.MIN_VALUE_4BYTE,
                VariableLengthInteger.MAX_VALUE_4BYTE,
                VariableLengthInteger.MIN_VALUE_8BYTE,
                VariableLengthInteger.MAX_VALUE_8BYTE
        };

        for ( VariableLengthInteger i : values ) {
            ByteBuffer byteBuffer = ByteBuffer.allocate( 8 /*maximum required number of bytes*/ );
            i.encode( byteBuffer );
            byteBuffer.rewind();
            VariableLengthInteger iTest = VariableLengthInteger.decode( byteBuffer );
            assertEquals( i, iTest );
        }
    }

}

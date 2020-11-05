package com.timtrense.quic;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class VariableLengthIntegerEncoderTest {

    @Test
    public void decode_givenSpecExample8_decodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 8 );
        buffer.put( new byte[]{(byte)0xc2, 0x19, 0x7c, 0x5e, (byte)0xff, 0x14, (byte)0xe8, (byte)0x8c} );
        buffer.position( 0 );

        long result = VariableLengthIntegerEncoder.decode( buffer );

        assertEquals( 151288809941952652L, result );
    }

    @Test
    public void decode_givenSpecExample4_decodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 4 );
        buffer.put( new byte[]{(byte)0x9d, 0x7f, 0x3e, 0x7d} );
        buffer.position( 0 );

        long result = VariableLengthIntegerEncoder.decode( buffer );

        assertEquals( 494878333L, result );
    }

    @Test
    public void decode_givenSpecExample2_decodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 2 );
        buffer.put( new byte[]{0x7b, (byte)0xbd} );
        buffer.position( 0 );

        long result = VariableLengthIntegerEncoder.decode( buffer );

        assertEquals( 15293L, result );
    }

    @Test
    public void decode_givenSpecExample1_decodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 1 );
        buffer.put( new byte[]{0x25} );
        buffer.position( 0 );

        long result = VariableLengthIntegerEncoder.decode( buffer );

        assertEquals( 37L, result );
    }

    @Test
    public void decode_givenSpecExample1_2_decodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 2 );
        buffer.put( new byte[]{0x40, 0x25} );
        buffer.position( 0 );

        long result = VariableLengthIntegerEncoder.decode( buffer );

        assertEquals( 37L, result );
    }

    @Test
    public void encode_givenSpecExample8_encodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 8 );
        buffer.put( new byte[]{(byte)0xc2, 0x19, 0x7c, 0x5e, (byte)0xff, 0x14, (byte)0xe8, (byte)0x8c} );
        buffer.position( 0 );

        ByteBuffer bufferTest = ByteBuffer.allocate( 8 );
        int encodeLength = VariableLengthIntegerEncoder.encode( 151288809941952652L, bufferTest );

        assertEquals( buffer.capacity(), encodeLength );
        assertArrayEquals( buffer.array(), bufferTest.array() );
    }

    @Test
    public void encode_givenSpecExample4_encodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 4 );
        buffer.put( new byte[]{(byte)0x9d, 0x7f, 0x3e, 0x7d} );
        buffer.position( 0 );

        ByteBuffer bufferTest = ByteBuffer.allocate( 4 );
        int encodeLength = VariableLengthIntegerEncoder.encode( 494878333L, bufferTest );

        assertEquals( buffer.capacity(), encodeLength );
        assertArrayEquals( buffer.array(), bufferTest.array() );
    }

    @Test
    public void encode_givenSpecExample2_encodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 2 );
        buffer.put( new byte[]{0x7b, (byte)0xbd} );
        buffer.position( 0 );

        ByteBuffer bufferTest = ByteBuffer.allocate( 2 );
        int encodeLength = VariableLengthIntegerEncoder.encode( 15293L, bufferTest );

        assertEquals( buffer.capacity(), encodeLength );
        assertArrayEquals( buffer.array(), bufferTest.array() );
    }

    @Test
    public void encode_givenSpecExample1_encodesCorrect() {
        ByteBuffer buffer = ByteBuffer.allocate( 1 );
        buffer.put( new byte[]{0x25} );
        buffer.position( 0 );

        ByteBuffer bufferTest = ByteBuffer.allocate( 1 );
        int encodeLength = VariableLengthIntegerEncoder.encode( 37L, bufferTest );

        assertEquals( buffer.capacity(), encodeLength );
        assertArrayEquals( buffer.array(), bufferTest.array() );
    }
}

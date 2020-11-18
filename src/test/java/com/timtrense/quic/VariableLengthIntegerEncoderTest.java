package com.timtrense.quic;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;

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

    @Test
    public void decodeFixedLengthInteger_byteArrayOfZeros_0() {
        long fli = VariableLengthIntegerEncoder.decodeFixedLengthInteger( new byte[]{0, 0, 0, 0, 0, 0}, 0, 1 );
        assertEquals( 0, fli );
    }

    @Test
    public void decodeFixedLengthInteger_byteArrayOfZerosWith17_17() {
        long fli = VariableLengthIntegerEncoder.decodeFixedLengthInteger( new byte[]{17, 0, 0, 0, 0, 0}, 0, 1 );
        assertEquals( 17, fli );
    }

    @Test
    public void decodeFixedLengthInteger_byteArrayOfZerosWith17Offset1_1() {
        long fli = VariableLengthIntegerEncoder.decodeFixedLengthInteger( new byte[]{0, 17, 0, 0, 0, 0}, 1, 1 );
        assertEquals( 17, fli );
    }

    @Test
    public void decodeFixedLengthInteger_byteArrayOfZerosWith17Length2_1() {
        long fli = VariableLengthIntegerEncoder.decodeFixedLengthInteger( new byte[]{0, 17, 0, 0, 0, 0}, 0, 2 );
        assertEquals( 17, fli );
    }

    @Test
    public void encodeFixedLengthInteger_0_byteArrayOfZeros() {
        byte[] out = new byte[10];
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( 0, out, 0, 4 );
        assertArrayEquals( new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, out );
    }

    @Test
    public void encodeFixedLengthInteger_1_byteArrayOfZerosLeading1() {
        byte[] out = new byte[10];
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( 1, out, 0, 1 );
        assertArrayEquals( new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, out );
    }

    @Test
    public void encodeFixedLengthInteger_17_byteArrayOfZerosLeading17() {
        byte[] out = new byte[10];
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( 17, out, 0, 1 );
        assertArrayEquals( new byte[]{17, 0, 0, 0, 0, 0, 0, 0, 0, 0}, out );
    }

    @Test
    public void encodeFixedLengthInteger_17Length2_byteArrayOfZerosLeading0And17() {
        byte[] out = new byte[10];
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( 17, out, 0, 2 );
        assertArrayEquals( new byte[]{0, 17, 0, 0, 0, 0, 0, 0, 0, 0}, out );
    }

    @Test
    public void encodeFixedLengthInteger_258Length2Offset1_byteArrayOfZerosLeading0And1And2() {
        byte[] out = new byte[10];
        VariableLengthIntegerEncoder.encodeFixedLengthInteger( 258, out, 1, 2 );
        assertArrayEquals( new byte[]{0, 1, 2, 0, 0, 0, 0, 0, 0, 0}, out );
    }
}

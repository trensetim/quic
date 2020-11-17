package com.timtrense.quic.impl.packets;

import org.junit.Test;

import com.timtrense.quic.ProtocolVersion;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.base.ConnectionIdImpl;
import com.timtrense.quic.impl.base.PacketNumberImpl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class InitialPacketImplTest {

    private static InitialPacketImpl createValid() {
        InitialPacketImpl validPacket = new InitialPacketImpl();
        validPacket.setFlags( (byte)0b11000001 );
        validPacket.setVersion( ProtocolVersion.ONE );
        validPacket.setPacketNumber( new PacketNumberImpl( 0L ) );
        validPacket.setDestinationConnectionIdLength( 1 );
        validPacket.setDestinationConnectionId( new ConnectionIdImpl(
                new byte[]{1}, com.timtrense.quic.VariableLengthInteger.ZERO ) );
        validPacket.setSourceConnectionIdLength( 1 );
        validPacket.setSourceConnectionId( new ConnectionIdImpl(
                new byte[]{2}, com.timtrense.quic.VariableLengthInteger.ZERO ) );
        validPacket.setTokenLength( VariableLengthInteger.ZERO );
        validPacket.setToken( null );
        return validPacket;
    }

    @Test
    public void isPacketValid_defaultValidValues_true() {
        InitialPacketImpl validPacket = createValid();
        assertTrue( validPacket.isPacketValid() );
    }

    @Test
    public void isPacketValid_mismatchingHeaderTypeBits_false() {
        InitialPacketImpl validPacket = createValid();
        validPacket.setFlags( (byte)0b11010001 );
        assertFalse( validPacket.isPacketValid() );
    }

    @Test
    public void getPacketLength_defaultValidValues_13() {
        InitialPacketImpl validPacket = createValid();
        assertEquals( 13, validPacket.getPacketLength() );
    }

    @Test
    public void getPacketNumberLength_defaultValidValues_2() {
        InitialPacketImpl validPacket = createValid();
        assertEquals( 2, validPacket.getPacketNumberLength() );
    }


}

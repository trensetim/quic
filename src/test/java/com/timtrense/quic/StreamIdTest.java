package com.timtrense.quic;

import com.timtrense.quic.impl.base.StreamIdImpl;
import org.junit.Test;

import static org.junit.Assert.*;

public class StreamIdTest {

    @Test
    public void getId_givenId_returnsSameId() {
        long streamIdValue = 17;
        StreamId streamId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        assertEquals( streamIdValue, streamId.getLongValue() );
    }

    @Test
    public void isUnidirectional_id2_true() {
        long streamIdValue = 2;
        StreamId streamId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        assertTrue( streamId.isUnidirectional() );
        assertFalse( streamId.isBidirectional() );
    }

    @Test
    public void isUnidirectional_id1_false() {
        long streamIdValue = 1;
        StreamId streamId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        assertFalse( streamId.isUnidirectional() );
        assertTrue( streamId.isBidirectional() );
    }

    @Test
    public void isClientInitiated_id2_true() {
        long streamIdValue = 2;
        StreamId streamId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        assertTrue( streamId.isClientInitiated() );
        assertFalse( streamId.isServerInitiated() );
    }

    @Test
    public void isClientInitiated_id1_false() {
        long streamIdValue = 1;
        StreamId streamId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        assertFalse( streamId.isClientInitiated() );
        assertTrue( streamId.isServerInitiated() );
    }
}

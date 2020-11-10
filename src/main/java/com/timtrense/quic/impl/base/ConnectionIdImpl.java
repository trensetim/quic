package com.timtrense.quic.impl.base;

import java.util.Arrays;
import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.VariableLengthInteger;

@Data
public class ConnectionIdImpl implements ConnectionId {

    private final @NonNull byte[] value;
    private final @NonNull VariableLengthInteger sequenceNumber;

    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public VariableLengthInteger getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public boolean equals( Object o ) {
        if ( this == o ) {
            return true;
        }
        if ( !( o instanceof ConnectionId ) ) {
            return false;
        }
        ConnectionId that = (ConnectionId)o;
        return Arrays.equals( value, that.getValue() );
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode( value );
    }
}

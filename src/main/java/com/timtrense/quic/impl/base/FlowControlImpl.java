package com.timtrense.quic.impl.base;

import lombok.Data;

import com.timtrense.quic.CreditBasedFlowControl;
import com.timtrense.quic.VariableLengthInteger;

@Data
public class FlowControlImpl implements CreditBasedFlowControl {

    private VariableLengthInteger limit;
    private VariableLengthInteger transferred;

    public FlowControlImpl( VariableLengthInteger limit ) {
        this.limit = limit;
        this.transferred = VariableLengthInteger.ZERO;
    }

    @Override
    public long getLimit() {
        return limit.getValue();
    }

    @Override
    public long getTransferred() {
        return transferred.getValue();
    }

    public VariableLengthInteger getVariableLengthIntegerLimit() {
        return limit;
    }

    public VariableLengthInteger getVariableLengthIntegerTransferred() {
        return transferred;
    }

    @Override
    public long incrementTransferred( int numberOfBytes ) {
        if ( numberOfBytes < 0 ) {
            throw new IllegalArgumentException( "Cannot increment the transferred number of bytes count by a negative" +
                    " amount of: " + numberOfBytes );
        }
        return ( transferred = transferred.increment( numberOfBytes ) ).longValue();
    }

    @Override
    public long incrementLimit( int numberOfBytes ) {
        if ( numberOfBytes < 0 ) {
            throw new IllegalArgumentException( "Cannot increment the limit number of bytes count by a negative " +
                    "amount of: " + numberOfBytes );
        }
        return ( limit = limit.increment( numberOfBytes ) ).longValue();
    }
}

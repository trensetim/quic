package com.timtrense.quic.impl.base;

import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Transport parameters which have integer values are encoded using {@link VariableLengthIntegerEncoder}
 *
 * @author Tim Trense
 */
@Data
@AllArgsConstructor
public class IntegerTransportParameterImpl implements TransportParameter<Long> {

    private TransportParameterType type;
    private long value;

    @Override
    public int getLength() {
        return VariableLengthIntegerEncoder.getLengthInBytes( value );
    }

    @Override
    public Long getValue() {
        return value;
    }
}

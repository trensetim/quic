package com.timtrense.quic.impl.base;

import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Transport parameters, which are flags, are omitted if the value is false, otherwise included, but always
 * have a length of zero.
 *
 * existing known flag frames are : {@link TransportParameterType#DISABLE_ACTIVE_MIGRATION}
 *
 * @author Tim Trense
 */
@Data
@AllArgsConstructor
public class FlagTransportParameterImpl implements TransportParameter<Boolean> {

    private TransportParameterType type;
    private boolean value;

    @Override
    public int getLength() {
        return 0;
    }

    @Override
    public Boolean getValue() {
        return value;
    }

}

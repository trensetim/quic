package com.timtrense.quic.impl.base;

import lombok.AllArgsConstructor;
import lombok.Data;

import com.timtrense.quic.PreferredAddress;
import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;

/**
 * Transport parameters which holds an {@link PreferredAddress}
 *
 * existing known flag frames are : {@link TransportParameterType#PREFERRED_ADDRESS}
 *
 * @author Tim Trense
 */
@Data
@AllArgsConstructor
public class PreferredAddressTransportParameterImpl implements TransportParameter<PreferredAddress> {

    private TransportParameterType type;
    private PreferredAddress value;

    @Override
    public int getLength() {
        return 0;
    }

    @Override
    public PreferredAddress getValue() {
        return value;
    }

}

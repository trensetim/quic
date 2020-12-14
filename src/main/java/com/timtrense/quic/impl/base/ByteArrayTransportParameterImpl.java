package com.timtrense.quic.impl.base;

import lombok.AllArgsConstructor;
import lombok.Data;

import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;

/**
 * Transport parameters which have byte-Arrays as values
 *
 * @author Tim Trense
 */
@Data
@AllArgsConstructor
public class ByteArrayTransportParameterImpl implements TransportParameter<byte[]> {

    private TransportParameterType type;
    private byte[] value;

    @Override
    public int getLength() {
        return value.length;
    }

    @Override
    public byte[] getValue() {
        return value;
    }
}

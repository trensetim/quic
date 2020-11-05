package com.timtrense.quic.impl.base;

import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;

@Data
public class StreamIdImpl implements com.timtrense.quic.StreamId {

    private final VariableLengthInteger value;

}

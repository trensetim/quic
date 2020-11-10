package com.timtrense.quic.impl.base;

import lombok.Data;

import com.timtrense.quic.VariableLengthInteger;

@Data
public class StreamIdImpl implements com.timtrense.quic.StreamId {

    private final VariableLengthInteger value;

}

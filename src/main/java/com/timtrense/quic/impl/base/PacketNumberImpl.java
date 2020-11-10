package com.timtrense.quic.impl.base;

import lombok.AllArgsConstructor;
import lombok.Data;

import com.timtrense.quic.PacketNumber;

@Data
@AllArgsConstructor
public class PacketNumberImpl implements PacketNumber {

    private long value;

}

package com.timtrense.quic.impl.base;

import com.timtrense.quic.PacketNumber;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PacketNumberImpl implements PacketNumber {

    private long value;

}

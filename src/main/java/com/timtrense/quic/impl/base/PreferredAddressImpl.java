package com.timtrense.quic.impl.base;

import lombok.Data;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.PreferredAddress;
import com.timtrense.quic.StatelessResetToken;

/**
 * Default implementation of {@link PreferredAddress}
 *
 * @author Tim Trense
 */
@Data
public class PreferredAddressImpl implements PreferredAddress {

    private byte[] ipv4Address;
    private int ipv4Port;

    private byte[] ipv6Address;
    private int ipv6Port;

    private ConnectionId connectionId;

    private StatelessResetToken statelessResetToken;

}

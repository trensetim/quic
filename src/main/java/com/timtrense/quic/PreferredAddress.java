package com.timtrense.quic;

/**
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#page-125">QUIC Spec/Page 125</a>
 */
public interface PreferredAddress {

    byte[] getIpv4Address();

    int getIpv4Port();

    byte[] getIpv6Address();

    int getIpv6Port();

    int getConnectionIdLength();

    byte[] getConnectionId();

    byte[] getStatelessResetToken();
}

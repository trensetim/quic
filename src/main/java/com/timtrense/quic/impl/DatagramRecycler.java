package com.timtrense.quic.impl;

import java.net.DatagramPacket;

/**
 * A disposer to re-use now-unneeded instances of {@link java.net.DatagramPacket DatagramPackets} to reduce the
 * need to re-allocate their byte-buffers
 *
 * @author Tim Trense
 */
public interface DatagramRecycler {

    /**
     * indicates the datagram as not being used anymore
     *
     * @param datagramPacket the datagram to give back for re-usage
     * @return whether the datagram was accepted (which may not be the case if the allowed
     * datagrams are constraint eg. by size of their buffers)
     */
    boolean giveBack( DatagramPacket datagramPacket );
}

package com.timtrense.quic.impl;

import java.net.DatagramPacket;
import java.util.concurrent.LinkedBlockingQueue;
import lombok.Getter;

/**
 * A pool of {@link DatagramPacket datagram packets} that holds datagrams that are yet to be used
 * while accepting to {@link #giveBack(DatagramPacket) give back} datagrams that were used.
 */
public class DatagramPool implements DatagramRecycler {

    /**
     * The INTERNAL queue to poll free datagrams from
     */
    private final LinkedBlockingQueue<DatagramPacket> pool;

    /**
     * The maximum number of bytes that a datagram may contain, thus the length of the allocated buffer
     */
    @Getter
    private int maxDatagramSize;

    /**
     * Creates a new pool that holds datagrams that all have exactly maxDatagramSize bytes of buffer
     *
     * @param poolSizeLimit   the maximum number of simultaneously hold datagrams in the pool.
     *                        Any more given back datagrams will be discarded.
     * @param maxDatagramSize {@link #maxDatagramSize}
     */
    public DatagramPool( int poolSizeLimit, int maxDatagramSize ) {
        pool = new LinkedBlockingQueue<>( poolSizeLimit );
        setMaxDatagramSize( maxDatagramSize );
    }

    /**
     * changes the maximum size that a {@link DatagramPacket} may contain in bytes.
     * By changing this size, all buffered datagrams are dropped and need to be reallocated.
     *
     * @param maxDatagramSize the new limit on the datagram size
     * @throws IllegalArgumentException if the limit is non-positive
     */
    public void setMaxDatagramSize( int maxDatagramSize ) {
        if ( maxDatagramSize <= 0 ) {
            throw new IllegalArgumentException( "Cannot set a non-positive maxDatagramSize" );
        }

        int oldMaxDatagramSize = this.maxDatagramSize;
        this.maxDatagramSize = maxDatagramSize;

        if ( maxDatagramSize != oldMaxDatagramSize ) {
            // drop all datagrams because they now have the wrong buffer size
            synchronized( pool ) {
                pool.clear();
            }
        }
    }

    /**
     * polls a {@link DatagramPacket} from the queue if available, otherwise creates one.
     * This method may return a previously returned instance but only after that instance was
     * {@link #giveBack(DatagramPacket) given back}, although there is no guarantee that any
     * given back instance will be returned eventually.
     *
     * @return a usable datagram, never null
     */
    public DatagramPacket take() {
        boolean isEmpty;
        synchronized( pool ) {
            isEmpty = pool.isEmpty();
        }
        if ( isEmpty ) {
            byte[] buffer = new byte[maxDatagramSize];
            return new DatagramPacket( buffer, buffer.length );
        }
        else {
            synchronized( pool ) {
                return pool.poll();
            }
        }
    }

    /**
     * @return the limit on the size if the buffering queue of datagrams
     */
    public int getPoolSizeLimit() {
        synchronized( pool ) {
            return pool.size() + pool.remainingCapacity();
        }
    }

    @Override
    public boolean giveBack( DatagramPacket datagramPacket ) {
        synchronized( pool ) {
            if ( datagramPacket.getLength() != maxDatagramSize ) {
                return false;
            }
            return pool.offer( datagramPacket );
        }
    }
}

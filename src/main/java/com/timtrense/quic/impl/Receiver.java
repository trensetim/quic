package com.timtrense.quic.impl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

/**
 * The {@link DatagramPacket datagrams} receiving thread
 *
 * @author Tim Trense
 */
@EqualsAndHashCode( callSuper = true )
public class Receiver extends Thread implements DatagramRecycler {

    /**
     * The socket to receive from
     */
    @Getter
    @Setter
    @NonNull
    private DatagramSocket socket;
    /**
     * The INTERNAL queue to poll empty, yet to fill, datagrams from
     */
    private final LinkedBlockingQueue<DatagramPacket> receiveQueue;
    /**
     * The maximum number of bytes that a datagram may contain, thus the length of the allocated buffer
     */
    @Getter
    private int maxDatagramSize;
    /**
     * The number of milliseconds the {@link Receiver#getTargetReceivedQueue()} may block before allowing
     * the {@link Receiver} to offer a new, received datagram. If this timeout elapses before the receiver can put
     * the new datagram to the queue, the receiver will go to {@link ReceiverState#ERROR} and will be stopped
     */
    @Getter
    private int receiveTargetBlockingTimeout;
    /**
     * The queue to write received datagrams to
     */
    @Getter
    private final @NonNull BlockingQueue<ReceivedDatagram> targetReceivedQueue;
    /**
     * the current state
     */
    @Getter
    private ReceiverState receiverState;
    /**
     * all registered listeners to notify about state changes
     */
    private final Set<ReceiverStateListener> stateListenerSet = new HashSet<>();

    /**
     * Creates a new receiver, reading from the given socket to the given target queue
     *
     * @param socket              the source to read datagrams from
     * @param targetReceivedQueue the queue to offer all received datagrams to
     * @param configuration       the initial configuration to apply
     */
    public Receiver(
            @NonNull DatagramSocket socket,
            @NonNull BlockingQueue<ReceivedDatagram> targetReceivedQueue,
            @NonNull EndpointConfiguration configuration
    ) {
        this.socket = socket;
        this.receiveQueue = new LinkedBlockingQueue<>( configuration.getReceiveDatagramQueueSizeLimit() );
        this.targetReceivedQueue = targetReceivedQueue;
        setMaxDatagramSize( configuration.getMaxDatagramSize() );
        receiveTargetBlockingTimeout = configuration.getReceiveTargetBlockingTimeout();
        this.receiverState = ReceiverState.NEW;

        setDaemon( true );
        setName( configuration.getEndpointName() + ".Receiver" );
    }

    /**
     * @return polls a {@link DatagramPacket} from the queue if available, otherwise creates one
     */
    private DatagramPacket poll() {
        boolean isEmpty;
        synchronized( receiveQueue ) {
            isEmpty = receiveQueue.isEmpty();
        }
        if ( isEmpty ) {
            byte[] buffer = new byte[maxDatagramSize];
            return new DatagramPacket( buffer, buffer.length );
        }
        else {
            synchronized( receiveQueue ) {
                return receiveQueue.poll();
            }
        }
    }

    /**
     * Offers a datagram to the queue to read to.
     *
     * @param datagram the datagram which can be filled
     * @return true if the datagram was added to the queue, false otherwise (presumably because queue is full or the
     * datagram does not match the required size constraints)
     */
    @Override
    public boolean giveBack( DatagramPacket datagram ) {
        if ( datagram == null ) {
            return false;
        }
        if ( datagram.getLength() != maxDatagramSize ) {
            return false;
        }
        return receiveQueue.offer( datagram );
    }

    @Override
    public void run() {
        setReceiverState( ReceiverState.ACTIVE );
        long counter = 0;
        boolean offered;
        try {
            while ( !isInterrupted() ) {
                try {
                    DatagramPacket datagram = poll();
                    socket.receive( datagram );
                    ReceivedDatagram receivedDatagram = new ReceivedDatagram(
                            datagram,
                            Instant.now(),
                            counter++,
                            (short)0
                    );
                    offered = targetReceivedQueue.offer(
                            receivedDatagram,
                            receiveTargetBlockingTimeout,
                            TimeUnit.MILLISECONDS
                    );
                    if ( !offered ) {
                        throw new IOException( "Timeout on offering a ReceivedDatagram to the target queue" );
                    }
                }
                catch ( InterruptedIOException | InterruptedException ignored ) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            setReceiverState( ReceiverState.STOP );
        }
        catch ( IOException e ) {
            e.printStackTrace();
            setReceiverState( ReceiverState.ERROR );
        }
    }

    /**
     * adds a listener to this receiver
     *
     * @param listener the listener to add
     */
    public void addListener( @NonNull ReceiverStateListener listener ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.add( listener );
        }
    }

    /**
     * removes the listener from this receiver
     *
     * @param listener the listener to remove
     */
    public void removeListener( @NonNull ReceiverStateListener listener ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.remove( listener );
        }
    }

    /**
     * changes the maximum size that a received datagram may contain in bytes.
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
            synchronized( receiveQueue ) {
                receiveQueue.clear();
            }
        }
    }

    /**
     * @return the limit on the size if the buffering queue of datagrams
     */
    public int getReceiveDatagramQueueSizeLimit() {
        synchronized( receiveQueue ) {
            return receiveQueue.size() + receiveQueue.remainingCapacity();
        }
    }

    /**
     * sets the value corresponding to {@link #getReceiveTargetBlockingTimeout()}
     *
     * @param receiveTargetBlockingTimeout the positive timeout in milliseconds to set
     */
    public void setReceiveTargetBlockingTimeout( int receiveTargetBlockingTimeout ) {
        if ( receiveTargetBlockingTimeout <= 0 ) {
            throw new IllegalArgumentException( "Cannot set a non-positive" +
                    " receiveTargetBlockingTimeout for a Receiver" );
        }
        this.receiveTargetBlockingTimeout = receiveTargetBlockingTimeout;
    }

    /**
     * calls all listeners and then updates the current state.
     * does no state transition allowance checks, thus is private
     *
     * @param newState the new state to transition to
     */
    private void setReceiverState( @NonNull ReceiverState newState ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.forEach( l -> {
                try {
                    l.beforeStateChange( Receiver.this, newState );
                }
                catch ( Exception e ) {
                    e.printStackTrace();
                }
            } );
        }
        receiverState = newState;
    }
}

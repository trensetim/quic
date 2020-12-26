package com.timtrense.quic.impl;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
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
public class Receiver extends Thread {

    /**
     * The INTERNAL pool to take empty, yet to fill, datagrams from
     */
    @Getter
    private final DatagramPool datagramPool;
    /**
     * The queue to write received datagrams to
     */
    @Getter
    private final @NonNull BlockingQueue<ReceivedDatagram> targetReceivedQueue;
    /**
     * all registered listeners to notify about state changes
     */
    private final Set<ReceiverStateListener> stateListenerSet = new HashSet<>();
    /**
     * The socket to receive from
     */
    @Getter
    @Setter
    @NonNull
    private DatagramSocket socket;
    /**
     * The number of milliseconds the {@link Receiver#getTargetReceivedQueue()} may block before allowing
     * the {@link Receiver} to offer a new, received datagram. If this timeout elapses before the receiver can put
     * the new datagram to the queue, the receiver will go to {@link ReceiverState#ERROR} and will be stopped
     */
    @Getter
    private int receiveTargetBlockingTimeout;
    /**
     * the current state
     */
    @Getter
    private ReceiverState receiverState;

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
        this.datagramPool = new DatagramPool(
                configuration.getReceiveDatagramQueueSizeLimit(),
                configuration.getMaxDatagramSize()
        );
        this.targetReceivedQueue = targetReceivedQueue;
        receiveTargetBlockingTimeout = configuration.getReceiveTargetBlockingTimeout();
        this.receiverState = ReceiverState.NEW;

        setDaemon( true );
        setName( configuration.getEndpointName() + ".Receiver" );
    }

    @Override
    public void run() {
        setReceiverState( ReceiverState.ACTIVE );
        long counter = 0;
        boolean offered;
        try {
            while ( !isInterrupted() ) {
                try {
                    DatagramPacket datagram = datagramPool.take();
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

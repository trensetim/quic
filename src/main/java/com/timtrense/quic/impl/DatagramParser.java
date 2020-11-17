package com.timtrense.quic.impl;

import java.io.IOException;
import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.Packet;
import com.timtrense.quic.impl.exception.MalformedDatagramException;
import com.timtrense.quic.impl.exception.OutOfOrderProtectedPacketException;

/**
 * A Parser to extract {@link Packet packets} from {@link ReceivedDatagram received datagrams}
 *
 * @author Tim Trense
 */
public class DatagramParser implements Runnable {

    /**
     * the queue to poll datagrams from
     */
    @Getter
    @NonNull
    private final BlockingQueue<ReceivedDatagram> parseQueue;
    /**
     * the queue to push packets to
     */
    @Getter
    @NonNull
    private final BlockingQueue<Packet> targetParsedQueue;
    /**
     * the recycler for fully parsed datagrams
     */
    @Getter
    @Setter
    private DatagramRecycler datagramRecycler;
    /**
     * The number of milliseconds the {@link #getTargetParsedQueue()} may block before allowing
     * the {@link DatagramParser} to offer a new, parsed {@link Packet}.
     * If this timeout elapses before the parser can put
     * the new packet to the queue, the parser will go to {@link DatagramParserState#ERROR} and will be stopped
     */
    @Getter
    private int parsedTargetBlockingTimeout;
    /**
     * the current state
     */
    @Getter
    private DatagramParserState state;
    /**
     * all registered listeners to notify about state changes
     */
    private final Set<DatagramParserStateListener> stateListenerSet = new HashSet<>();

    /**
     * The algorithm used to parse packets
     */
    @Getter
    @Setter
    private @NonNull PacketParser packetParser;

    /**
     * Creates a new parser, reading from an internally created parseQueue to the given target queue
     *
     * @param targetReceivedQueue the queue to offer all received packets to
     * @param configuration       the initial configuration
     */
    public DatagramParser(
            @NonNull BlockingQueue<Packet> targetReceivedQueue,
            @NonNull EndpointConfiguration configuration,
            @NonNull PacketParser packetParser
    ) {
        this.targetParsedQueue = targetReceivedQueue;
        this.parseQueue = new LinkedBlockingQueue<>( configuration.getParseDatagramQueueSizeLimit() );
        this.packetParser = packetParser;
        setParsedTargetBlockingTimeout( configuration.getParsedTargetBlockingTimeout() );
        this.state = DatagramParserState.NEW;
    }

    @Override
    public void run() {
        setState( DatagramParserState.ACTIVE );
        boolean offered;
        List<Packet> packets = new ArrayList<>( 5 );
        DatagramPacket datagram = null;
        try {
            parsingPackets:
            while ( !Thread.currentThread().isInterrupted() ) {
                try {
                    if ( datagramRecycler != null && datagram != null ) {
                        datagramRecycler.giveBack( datagram );
                    }
                    packets.clear();

                    ReceivedDatagram receivedDatagram;
                    receivedDatagram = parseQueue.take();
                    datagram = receivedDatagram.getDatagram();

                    try {
                        ByteBuffer data = ByteBuffer.wrap( datagram.getData(),
                                datagram.getOffset(), datagram.getLength() );

                        int packetIndex = 0;
                        while ( data.remaining() > 0 ) {
                            Packet p = packetParser.parsePacket( receivedDatagram, data, packetIndex );
                            if ( p == null ) {
                                throw new MalformedDatagramException( receivedDatagram, data );
                            }
                            packets.add( p );
                            packetIndex++;
                        }

                    }
                    catch ( OutOfOrderProtectedPacketException ignored ) {
                        synchronized( parseQueue ) {
                            /*offered =*/
                            parseQueue.offer( receivedDatagram, 250, TimeUnit.MILLISECONDS );
                            // if we cannot offer again, just drop the datagram. it was out-of-order anyway and
                            // the peer will retransmit it if necessary
                        }
                        continue /*parsingPackets*/;
                    }
                    catch ( Exception e ) {
                        e.printStackTrace();
                        // if datagrams are unable to be FULLY parsed, just drop them
                        continue /*parsingPackets*/;
                    }

                    ConnectionId connectionForDatagram = null;
                    for ( Packet p : packets ) {
                        if ( connectionForDatagram == null ) {

                            // this cannot be null, because that would be illegal
                            // and would have thrown an error while parsing
                            connectionForDatagram = p.getDestinationConnectionId();
                        }
                        else if ( !connectionForDatagram.equals( p.getDestinationConnectionId() ) ) {
                            // "Senders MUST NOT coalesce QUIC packets with different connection IDs into
                            // a single UDP datagram." QUIC Spec/Section 12.2
                            continue parsingPackets; // drop entire datagram
                        }
                    }
                    for ( Packet p : packets ) {
                        synchronized( targetParsedQueue ) {
                            offered = targetParsedQueue.offer( p, parsedTargetBlockingTimeout, TimeUnit.MILLISECONDS );
                        }
                        if ( !offered ) {
                            throw new IOException( "Timeout on offering a Packet to the target queue" );
                        }
                    }
                }
                catch ( InterruptedException ignored ) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            setState( DatagramParserState.STOP );
        }
        catch ( Exception e ) {
            e.printStackTrace();
            setState( DatagramParserState.ERROR );
        }
    }

    /**
     * @return the limit on the size if the buffering queue of datagrams
     */
    public int getParseDatagramQueueSizeLimit() {
        synchronized( parseQueue ) {
            return parseQueue.size() + parseQueue.remainingCapacity();
        }
    }

    /**
     * sets the value corresponding to {@link #getParsedTargetBlockingTimeout()} ()}
     *
     * @param parsedTargetBlockingTimeout the positive timeout in milliseconds to set
     */
    public void setParsedTargetBlockingTimeout( int parsedTargetBlockingTimeout ) {
        if ( parsedTargetBlockingTimeout <= 0 ) {
            throw new IllegalArgumentException( "Cannot set a non-positive" +
                    " parsedTargetBlockingTimeout for a DatagramParser" );
        }
        this.parsedTargetBlockingTimeout = parsedTargetBlockingTimeout;
    }

    /**
     * adds a listener to this receiver
     *
     * @param listener the listener to add
     */
    public void addListener( @NonNull DatagramParserStateListener listener ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.add( listener );
        }
    }

    /**
     * removes the listener from this receiver
     *
     * @param listener the listener to remove
     */
    public void removeListener( @NonNull DatagramParserStateListener listener ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.remove( listener );
        }
    }

    /**
     * calls all listeners and then updates the current state.
     * does no state transition allowance checks, thus is private
     *
     * @param newState the new state to transition to
     */
    private void setState( @NonNull DatagramParserState newState ) {
        synchronized( stateListenerSet ) {
            stateListenerSet.forEach( l -> {
                try {
                    l.beforeStateChange( DatagramParser.this, newState );
                }
                catch ( Exception e ) {
                    e.printStackTrace();
                }
            } );
        }
        state = newState;
    }

}

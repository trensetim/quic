package com.timtrense.quic.impl;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.impl.base.TransportParameterCollection;
import com.timtrense.quic.impl.base.TransportParameterCollectionImpl;

import java.security.SecureRandom;
import java.util.Random;

/**
 * All configuration parameters for an {@link Endpoint}
 *
 * @author Tim Trense
 */
@Data
public class EndpointConfiguration {

    /**
     * The source of randomness to apply globally to the endpoint
     */
    private @NonNull Random random = new SecureRandom();

    private @NonNull TransportParameterCollection transportParameters = new TransportParameterCollectionImpl();
    /**
     * The maximum amount of bytes a datagram may carry.
     * Default = 1600, because most networks MTU is 1500 + a little buffer
     */
    private int maxDatagramSize = 1600;

    /**
     * @see Receiver#getReceiveDatagramQueueSizeLimit()
     */
    private int receiveDatagramQueueSizeLimit = 3;

    /**
     * @see DatagramParser#getParseDatagramQueueSizeLimit()
     */
    private int parseDatagramQueueSizeLimit = 10;

    /**
     * @see Receiver#getReceiveTargetBlockingTimeout()
     */
    private int receiveTargetBlockingTimeout = 1000;
    /**
     * @see DatagramParser#getParsedTargetBlockingTimeout()
     */
    private int parsedTargetBlockingTimeout = 1000;

    /**
     * A name of the endpoint that may be used to identify it within: thread names, log messages etc.
     */
    private String endpointName = Endpoint.class.getName();
}

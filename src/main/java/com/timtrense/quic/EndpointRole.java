package com.timtrense.quic;

/**
 * QUIC is a client/server-based protocol. So any endpoint EITHER is a {@link #CLIENT} or a {@link #SERVER}
 *
 * @author Tim Trense
 */
public enum EndpointRole {

    CLIENT,

    SERVER
}

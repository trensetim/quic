package com.timtrense.quic.impl.exception;

import lombok.Getter;

/**
 * This implementation does not support the indicated {@link com.timtrense.quic.ProtocolVersion} of QUIC
 *
 * @author Tim Trense
 */
public class UnsupportedProtocolVersionException extends QuicParsingException {

    @Getter
    private final int version;

    public UnsupportedProtocolVersionException( int version ) {
        super( "The ProtocolVersion is not supported: " + version );
        this.version = version;
    }
}

package com.timtrense.quic.impl.exception;

/**
 * The crypto content is no valid TLS message
 *
 * @author Tim Trense
 */
public class MalformedTlsException extends QuicParsingException {

    public MalformedTlsException(
            String message
    ) {
        super( message );
    }
}

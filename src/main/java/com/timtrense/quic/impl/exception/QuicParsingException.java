package com.timtrense.quic.impl.exception;

/**
 * Base class for all exceptions thrown by this implementation, related to parsing data sent to this protocol
 *
 * @author Tim Trense
 */
public abstract class QuicParsingException extends Exception {

    public QuicParsingException( String message ) {
        super( message, null, false, false );
    }

    public QuicParsingException( String message, Throwable cause, boolean writableStackTrace ) {
        super( message, cause, false, writableStackTrace );
    }
}

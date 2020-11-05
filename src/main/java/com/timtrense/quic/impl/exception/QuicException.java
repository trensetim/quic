package com.timtrense.quic.impl.exception;

/**
 * Base class for all exceptions throws by this implementation, related to the protocol itself
 *
 * @author Tim Trense
 */
public abstract class QuicException extends Exception {

    public QuicException( String message ) {
        super( message );
    }

    public QuicException( String message, Throwable cause, boolean writableStackTrace ) {
        super( message, cause, true, writableStackTrace );
    }
}

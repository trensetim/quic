package com.timtrense.quic.impl;

/**
 * The state that a {@link DatagramParser} may have.
 * It always has one.
 *
 * @author Tim Trense
 */
public enum DatagramParserState {

    /**
     * INITIAL STATE.
     * The parser was instantiated but is not yet running
     */
    NEW,
    /**
     * The parsers thread started
     */
    ACTIVE,
    /**
     * TERMINAL STATE.
     * The parser threw an unrecoverable error
     */
    ERROR,
    /**
     * TERMINAL STATE.
     * The parser stopped gracefully and the parsing thread is about to die
     */
    STOP

}

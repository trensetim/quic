package com.timtrense.quic.impl;

/**
 * The state that a {@link Receiver} may have.
 * It always has one.
 *
 * @author Tim Trense
 */
public enum ReceiverState {

    /**
     * INITIAL STATE.
     * The receiver was instantiated but is not yet running
     */
    NEW,
    /**
     * The receivers thread started
     */
    ACTIVE,
    /**
     * TERMINAL STATE.
     * The receiving threw an unrecoverable error
     */
    ERROR,
    /**
     * TERMINAL STATE.
     * The receiving stopped gracefully and the receiving thread is about to die
     */
    STOP

}

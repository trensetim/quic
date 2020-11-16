package com.timtrense.quic.impl;

/**
 * Listener for changes of the {@link ReceiverState} of an {@link Receiver}
 *
 * @author Tim Trense
 */
public interface ReceiverStateListener {

    /**
     * Called with the receiver still being in the old state.
     *
     * @param receiver the receiver that's state is transitioning
     * @param newState the state the receiver will be in, any time after this call
     */
    void beforeStateChange( Receiver receiver, ReceiverState newState );
}

package com.timtrense.quic.impl;

/**
 * Listener for changes of the {@link DatagramParserState} of a {@link DatagramParser}
 *
 * @author Tim Trense
 */
public interface DatagramParserStateListener {

    /**
     * Called with the parser still being in the old state.
     *
     * @param parser   the parser that's state is transitioning
     * @param newState the state the parser will be in, any time after this call
     */
    void beforeStateChange( DatagramParser parser, DatagramParserState newState );
}

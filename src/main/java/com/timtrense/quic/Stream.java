package com.timtrense.quic;

/**
 * Ordered Byte-Stream to send and/or receive data.
 *
 * <p/>
 * <p/>
 * <h2>Operations on Streams</h2>
 * This document does not define an API for QUIC, but instead defines a
 * set of functions on streams that application protocols can rely upon.
 * An application protocol can assume that a QUIC implementation
 * provides an interface that includes the operations described in this
 * section.  An implementation designed for use with a specific
 * application protocol might provide only those operations that are
 * used by that protocol.
 *
 * On the sending part of a stream, an application protocol can:
 *
 * <ul>
 * <li>
 *  write data, understanding when stream flow control credit
 * (Section 4.1) has successfully been reserved to send the written
 * data;
 * </li>
 * <li>
 *  end the stream (clean termination), resulting in a STREAM frame
 * (Section 19.8) with the FIN bit set; and
 * </li>
 * <li>
 * reset the stream (abrupt termination), resulting in a RESET_STREAM
 * frame (Section 19.4) if the stream was not already in a terminal
 * state.
 * </li>
 * </ul>
 * On the receiving part of a stream, an application protocol can:
 *
 * <ul>
 * <li>
 *  read data; and
 * </li>
 * <li>
 *  abort reading of the stream and request closure, possibly
 * resulting in a STOP_SENDING frame (Section 19.5).
 * </li>
 * </ul>
 * An application protocol can also request to be informed of state
 * changes on streams, including when the peer has opened or reset a
 * stream, when a peer aborts reading on a stream, when new data is
 * available, and when data can or cannot be written to the stream due
 * to flow control.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-2">QUIC Spec/Section 2</a>
 */
public interface Stream {

    /**
     * @return the identifier of this stream, unique within a connection, not null
     */
    StreamId getId();

    /**
     * @return the current priority of the stream, not null
     */
    StreamPriority getPriority();

    /**
     * @param priority the new priority of the stream, not null
     */
    void setPriority( StreamPriority priority );

    /**
     * @return the state that this stream is currently in for sending data, not null
     */
    StreamState getCurrentSendingState();

    /**
     * @return the state that this stream is currently in for receiving data, not null
     */
    StreamState getCurrentReceivingState();

    /**
     * The current version of QUIC uses a credit based flow control.
     *
     * @return the flow control limits set by the peer
     */
    CreditBasedFlowControl getSendingFlowControl();

    /**
     * The current version of QUIC uses a credit based flow control.
     *
     * @return the flow control limits set by this endpoint
     */
    CreditBasedFlowControl getReceivingFlowControl();

}

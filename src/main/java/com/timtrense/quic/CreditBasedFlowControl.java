package com.timtrense.quic;

/**
 * See: {@link FlowControl} for general information on flow control.
 *
 * QUIC employs a limit-based flow-control scheme where a receiver
 * advertises the limit of total bytes it is prepared to receive on a
 * given stream or for the entire connection.  This leads to two levels
 * of data flow control in QUIC:
 *
 * <ul>
 *     <li>
 *         Stream flow control, which prevents a single stream from consuming
 *       the entire receive buffer for a connection by limiting the amount
 *       of data that can be sent on any stream.
 *     </li>
 *     <li>
 *         Connection flow control, which prevents senders from exceeding a
 *       receiver's buffer capacity for the connection, by limiting the
 *       total bytes of stream data sent in STREAM frames on all streams.
 *     </li>
 * </ul>
 *
 * <b>Senders MUST NOT send data in excess of either limit.</b>
 *
 * A receiver sets initial limits for all streams through transport
 * parameters during the handshake (Section 7.4).  Subsequently, a
 * receiver sends MAX_STREAM_DATA (Section 19.10) or MAX_DATA
 * (Section 19.9) frames to the sender to advertise larger limits.
 *
 * A receiver can advertise a larger limit for a stream by sending a
 * MAX_STREAM_DATA frame with the corresponding stream ID.  A
 * MAX_STREAM_DATA frame indicates the maximum absolute byte offset of a
 * stream.  A receiver could determine the flow control offset to be
 * advertised based on the current offset of data consumed on that
 * stream.
 *
 * A receiver can advertise a larger limit for a connection by sending a
 * MAX_DATA frame, which indicates the maximum of the sum of the
 * absolute byte offsets of all streams.  A receiver maintains a
 * cumulative sum of bytes received on all streams, which is used to
 * check for violations of the advertised connection or stream data
 * limits.  A receiver could determine the maximum data limit to be
 * advertised based on the sum of bytes consumed on all streams.
 *
 * Once a receiver advertises a limit for the connection or a stream, it
 * MAY advertise a smaller limit, but this has no effect.
 *
 * A receiver MUST close the connection with a FLOW_CONTROL_ERROR error
 * (Section 11) if the sender violates the advertised connection or
 * stream data limits.
 *
 * A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do
 * not increase flow control limits.
 *
 * If a sender has sent data up to the limit, it will be unable to send
 * new data and is considered blocked.  A sender SHOULD send a
 * STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
 * that it has data to write but is blocked by flow control limits.  If
 * a sender is blocked for a period longer than the idle timeout
 * (Section 10.1), the receiver might close the connection even when the
 * sender has data that is available for transmission.  To keep the
 * connection from closing, a sender that is flow control limited SHOULD
 * periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it
 * has no ack-eliciting packets in flight.
 *
 * <p/>
 * <h2>Increasing Flow Control Limits</h2>
 * Implementations decide when and how much credit to advertise in
 * MAX_STREAM_DATA and MAX_DATA frames, but this section offers a few
 * considerations.
 *
 * To avoid blocking a sender, a receiver MAY send a MAX_STREAM_DATA or
 * MAX_DATA frame multiple times within a round trip or send it early
 * enough to allow time for loss of the frame and subsequent recovery.
 *
 * Control frames contribute to connection overhead.  Therefore,
 * frequently sending MAX_STREAM_DATA and MAX_DATA frames with small
 * changes is undesirable.  On the other hand, if updates are less
 * frequent, larger increments to limits are necessary to avoid blocking
 * a sender, requiring larger resource commitments at the receiver.
 * There is a trade-off between resource commitment and overhead when
 * determining how large a limit is advertised.
 *
 * A receiver can use an autotuning mechanism to tune the frequency and
 * amount of advertised additional credit based on a round-trip time
 * estimate and the rate at which the receiving application consumes
 * data, similar to common TCP implementations.  As an optimization, an
 * endpoint could send frames related to flow control only when there
 * are other frames to send, ensuring that flow control does not cause
 * extra packets to be sent.
 *
 * A blocked sender is not required to send STREAM_DATA_BLOCKED or
 * DATA_BLOCKED frames.  Therefore, a receiver MUST NOT wait for a
 * STREAM_DATA_BLOCKED or DATA_BLOCKED frame before sending a
 * MAX_STREAM_DATA or MAX_DATA frame; doing so could result in the
 * sender being blocked for the rest of the connection.  Even if the
 * sender sends these frames, waiting for them will result in the sender
 * being blocked for at least an entire round trip.
 *
 * When a sender receives credit after being blocked, it might be able
 * to send a large amount of data in response, resulting in short-term
 * congestion; see Section 6.9 in [QUIC-RECOVERY] for a discussion of
 * how a sender can avoid this congestion.
 *
 * <p/>
 * <h2>Flow Control Performance</h2>
 * If an endpoint cannot ensure that its peer always has available flow
 * control credit that is greater than the peer's bandwidth-delay
 * product on this connection, its receive throughput will be limited by
 * flow control.
 *
 * Packet loss can cause gaps in the receive buffer, preventing the
 * application from consuming data and freeing up receive buffer space.
 *
 * Sending timely updates of flow control limits can improve
 * performance.  Sending packets only to provide flow control updates
 * can increase network load and adversely affect performance.  Sending
 * flow control updates along with other frames, such as ACK frames,
 * reduces the cost of those updates.
 *
 *
 * <p/>
 * <h2>Stream Final Size</h2>
 * The final size is the amount of flow control credit that is consumed
 * by a stream.  Assuming that every contiguous byte on the stream was
 * sent once, the final size is the number of bytes sent.  More
 * generally, this is one higher than the offset of the byte with the
 * largest offset sent on the stream, or zero if no bytes were sent.
 *
 * A sender always communicates the final size of a stream to the
 * receiver reliably, no matter how the stream is terminated.  The final
 * size is the sum of the Offset and Length fields of a STREAM frame
 * with a FIN flag, noting that these fields might be implicit.
 * Alternatively, the Final Size field of a RESET_STREAM frame carries
 * this value.  This guarantees that both endpoints agree on how much
 * flow control credit was consumed by the sender on that stream.
 *
 * An endpoint will know the final size for a stream when the receiving
 * part of the stream enters the "Size Known" or "Reset Recvd" state
 * (Section 3).  The receiver MUST use the final size of the stream to
 * account for all bytes sent on the stream in its connection level flow
 * controller.
 *
 * An endpoint MUST NOT send data on a stream at or beyond the final
 * size.
 *
 * Once a final size for a stream is known, it cannot change.  If a
 * RESET_STREAM or STREAM frame is received indicating a change in the
 * final size for the stream, an endpoint SHOULD respond with a
 * FINAL_SIZE_ERROR error; see Section 11.  A receiver SHOULD treat
 * receipt of data at or beyond the final size as a FINAL_SIZE_ERROR
 * error, even after a stream is closed.  Generating these errors is not
 * mandatory, because requiring that an endpoint generate these errors
 * also means that the endpoint needs to maintain the final size state
 * for closed streams, which could mean a significant state commitment.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-4">QUIC Spec/Section 4</a>
 */
public interface CreditBasedFlowControl extends FlowControl {

    /**
     * For a sender, this limit indicates the maximum number of bytes it may send to the receiver either for the
     * applied stream or in total.
     *
     * @return the current limit set for the number of bytes allowed to transfer
     */
    long getLimit();

    /**
     * @return the currently transferred number of bytes
     */
    long getTransferred();

    /**
     * Increments the internal counter for number of transferred bytes.
     * This might get called upon receiving an {@link FrameGeneralType#ACK} frame
     *
     * Implementations MUST throw an IllegalArgumentException if the numberOfBytes is BELOW zero.
     *
     * @param numberOfBytes the amount to increment by
     * @return the new (incremented) number of transferred bytes
     */
    long incrementTransferred( int numberOfBytes );

    /**
     * Increments the internal counter for limit of transferable bytes.
     * This might be called upon receiving of a {@link FrameGeneralType#MAX_DATA} or
     * {@link FrameGeneralType#MAX_STREAM_DATA} frame.
     *
     * Implementations MUST throw an IllegalArgumentException if the numberOfBytes is BELOW zero.
     *
     * @param numberOfBytes the amount to increment by
     * @return the new (incremented) limit of transferable bytes
     */
    long incrementLimit( int numberOfBytes );

    /**
     * @param numberOfBytes the amount the caller tries to send
     * @return true if the currently transferred number of bytes PLUS the given numberOfBytes does not exceed the limit
     */
    @Override
    default boolean canSend( int numberOfBytes ) {
        return getTransferred() + numberOfBytes <= getLimit();
    }

    /**
     * @return the remaining number of bytes that can be transferred before exceeding the limit
     */
    default long getCredit() {
        return getLimit() - getTransferred();
    }
}

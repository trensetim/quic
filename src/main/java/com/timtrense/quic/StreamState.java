package com.timtrense.quic;

/**
 * This section describes streams in terms of their send or receive
 * components.  Two state machines are described: one for the streams on
 * which an endpoint transmits data (Section 3.1), and another for
 * streams on which an endpoint receives data (Section 3.2).
 *
 * Unidirectional streams use the applicable state machine directly.
 * <b>Bidirectional streams use both state machines.</b>  For the most part,
 * the use of these state machines is the same whether the stream is
 * unidirectional or bidirectional.  The conditions for opening a stream
 * are slightly more complex for a bidirectional stream because the
 * opening of either the send or receive side causes the stream to open
 * in both directions.
 *
 * <b>The state machines shown in this section are largely informative.</b>
 * This document uses stream states to describe rules for when and how
 * different types of frames can be sent and the reactions that are
 * expected when different types of frames are received.  Though these
 * state machines are intended to be useful in implementing QUIC, these
 * states are not intended to constrain implementations.  <b>An
 * implementation can define a different state machine as long as its
 * behavior is consistent with an implementation that implements these
 * states.</b>
 *
 * Note:  In some cases, a single event or action can cause a transition
 * through multiple states.  For instance, sending STREAM with a FIN
 * bit set can cause two state transitions for a sending stream: from
 * the Ready state to the Send state, and from the Send state to the
 * Data Sent state.
 *
 * <p/>
 * <h2>Bidirectional Stream States</h2>
 * A bidirectional stream is composed of sending and receiving parts.
 * Implementations may represent states of the bidirectional stream as
 * composites of sending and receiving stream states.  The simplest
 * model presents the stream as "open" when either sending or receiving
 * parts are in a non-terminal state and "closed" when both sending and
 * receiving streams are in terminal states.
 *
 * Table 2 shows a more complex mapping of bidirectional stream states
 * that loosely correspond to the stream states in HTTP/2 [HTTP2].  This
 * shows that multiple states on sending or receiving parts of streams
 * are mapped to the same composite state.  Note that this is just one
 * possibility for such a mapping; this mapping requires that data is
 * acknowledged before the transition to a "closed" or "half-closed"
 * state.
 *
 * Note (*1):  A stream is considered "idle" if it has not yet been
 * created, or if the receiving part of the stream is in the "Recv"
 * state without yet having received any frames.
 *
 * <p/>
 * <h2>Handling Stream Cancellation</h2>
 * Endpoints need to eventually agree on the amount of flow control
 * credit that has been consumed on every stream, to be able to account
 * for all bytes for connection-level flow control.
 *
 * On receipt of a RESET_STREAM frame, an endpoint will tear down state
 * for the matching stream and ignore further data arriving on that
 * stream.
 *
 * RESET_STREAM terminates one direction of a stream abruptly.  For a
 * bidirectional stream, RESET_STREAM has no effect on data flow in the
 * opposite direction.  Both endpoints MUST maintain flow control state
 * for the stream in the unterminated direction until that direction
 * enters a terminal state.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-3">QUIC Spec/Section 3</a>
 */
public interface StreamState {
}

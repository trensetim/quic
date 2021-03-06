package com.timtrense.quic.impl.base;

import com.timtrense.quic.StreamState;

/**
 * <pre>
 *           o
 *           | Create Stream (Sending)
 *           | Peer Creates Bidirectional Stream
 *           v
 *       +-------+
 *       | Ready | Send RESET_STREAM
 *       |       |-----------------------.
 *       +-------+                       |
 *           |                           |
 *           | Send STREAM /             |
 *           |      STREAM_DATA_BLOCKED  |
 *           |                           |
 *           | Peer Creates              |
 *           |      Bidirectional Stream |
 *           v                           |
 *       +-------+                       |
 *       | Send  | Send RESET_STREAM     |
 *       |       |---------------------->|
 *       +-------+                       |
 *           |                           |
 *           | Send STREAM + FIN         |
 *           v                           v
 *       +-------+                   +-------+
 *       | Data  | Send RESET_STREAM | Reset |
 *       | Sent  |------------------>| Sent  |
 *       +-------+                   +-------+
 *           |                           |
 *           | Recv All ACKs             | Recv ACK
 *           v                           v
 *       +-------+                   +-------+
 *       | Data  |                   | Reset |
 *       | Recvd |                   | Recvd |
 *       +-------+                   +-------+
 * </pre>
 *
 * The sending part of a stream that the endpoint initiates (types 0 and
 * 2 for clients, 1 and 3 for servers) is opened by the application.
 * The "Ready" state represents a newly created stream that is able to
 * accept data from the application.  Stream data might be buffered in
 * this state in preparation for sending.
 *
 * Sending the first STREAM or STREAM_DATA_BLOCKED frame causes a
 * sending part of a stream to enter the "Send" state.  An
 * implementation might choose to defer allocating a stream ID to a
 * stream until it sends the first STREAM frame and enters this state,
 * which can allow for better stream prioritization.
 *
 * The sending part of a bidirectional stream initiated by a peer (type
 * 0 for a server, type 1 for a client) starts in the "Ready" state when
 * the receiving part is created.
 *
 * In the "Send" state, an endpoint transmits - and retransmits as
 * necessary - stream data in STREAM frames.  The endpoint respects the
 * flow control limits set by its peer, and continues to accept and
 * process MAX_STREAM_DATA frames.  An endpoint in the "Send" state
 * generates STREAM_DATA_BLOCKED frames if it is blocked from sending by
 * stream or connection flow control limits Section 4.1.
 *
 * After the application indicates that all stream data has been sent
 * and a STREAM frame containing the FIN bit is sent, the sending part
 * of the stream enters the "Data Sent" state.  From this state, the
 * endpoint only retransmits stream data as necessary.  The endpoint
 * does not need to check flow control limits or send
 * STREAM_DATA_BLOCKED frames for a stream in this state.
 * MAX_STREAM_DATA frames might be received until the peer receives the
 * final stream offset.  The endpoint can safely ignore any
 * MAX_STREAM_DATA frames it receives from its peer for a stream in this
 * state.
 *
 * Once all stream data has been successfully acknowledged, the sending
 * part of the stream enters the "Data Recvd" state, which is a terminal
 * state.
 *
 * From any of the "Ready", "Send", or "Data Sent" states, an
 * application can signal that it wishes to abandon transmission of
 * stream data.  Alternatively, an endpoint might receive a STOP_SENDING
 * frame from its peer.  In either case, the endpoint sends a
 * RESET_STREAM frame, which causes the stream to enter the "Reset Sent"
 * state.
 *
 * An endpoint MAY send a RESET_STREAM as the first frame that mentions
 * a stream; this causes the sending part of that stream to open and
 * then immediately transition to the "Reset Sent" state.
 *
 * Once a packet containing a RESET_STREAM has been acknowledged, the
 * sending part of the stream enters the "Reset Recvd" state, which is a
 * terminal state.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-3.1">QUIC Spec/Section 3.1</a>
 */
public enum SendingStreamStateImpl implements StreamState {

    NEW,
    READY,
    SEND,
    DATA_SENT,
    RESET_SENT,
    DATA_RECEIVED,
    RESET_RECEIVED

}

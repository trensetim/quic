package com.timtrense.quic;

/**
 * general fully distinct types of frames
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19">QUIC Spec/Section 19</a>
 * @see FrameType
 */
public enum FrameGeneralType {

    PADDING,
    PING,
    ACK,
    RESET_STREAM,
    STOP_SENDING,
    CRYPTO,
    NEW_TOKEN,
    STREAM,
    MAX_DATA,
    MAX_STREAM_DATA,
    MAX_STREAMS,
    DATA_BLOCKED,
    STREAM_DATA_BLOCKED,
    STREAMS_BLOCKED,
    NEW_CONNECTION_ID,
    RETIRE_CONNECTION_ID,
    PATH_CHALLENGE,
    PATH_RESPONSE,
    CONNECTION_CLOSE,
    HANDSHAKE_DONE
}

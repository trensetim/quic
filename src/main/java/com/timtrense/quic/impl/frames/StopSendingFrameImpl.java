package com.timtrense.quic.impl.frames;

import lombok.Data;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;

/**
 * stop sending frame.
 * existing known frames are : {@link FrameType#STOP_SENDING}
 *
 * An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that
 * incoming data is being discarded on receipt at application request.
 * STOP_SENDING requests that a peer cease transmission on a stream.
 *
 * A STOP_SENDING frame can be sent for streams in the Recv or Size
 * Known states; see Section 3.1.  Receiving a STOP_SENDING frame for a
 * locally-initiated stream that has not yet been created MUST be
 * treated as a connection error of type STREAM_STATE_ERROR.  An
 * endpoint that receives a STOP_SENDING frame for a receive-only stream
 * MUST terminate the connection with error STREAM_STATE_ERROR.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.5">QUIC Spec/Section 19.5</a>
 */
@Data
public class StopSendingFrameImpl implements Frame {

    private final FrameType type;

    public StopSendingFrameImpl( FrameType type ) {
        this.type = type;
        if ( type.getGeneralType() != FrameGeneralType.STOP_SENDING ) {
            throw new IllegalArgumentException(
                    "Cannot build an ResetStreamFrame with FrameGeneralType other than "
                            + FrameGeneralType.STOP_SENDING.name()
            );
        }
    }

    /**
     * A variable-length integer carrying the Stream ID of the stream being ignored
     */
    private StreamId streamId;

    /**
     * A variable-length integer
     * containing the application-specified reason the sender is ignoring
     * the stream; see Section 20.2
     */
    private VariableLengthInteger applicationProtocolErrorCode;

    @Override
    public boolean isValid() {
        return streamId != null
                && applicationProtocolErrorCode != null;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += streamId.getValue().getEncodedLengthInBytes();
        sum += applicationProtocolErrorCode.getEncodedLengthInBytes();
        return sum;
    }
}

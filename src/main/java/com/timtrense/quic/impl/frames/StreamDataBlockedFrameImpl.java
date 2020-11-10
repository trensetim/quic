package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;

/**
 * stream data blocked frame.
 * existing known frames are : {@link FrameGeneralType#STREAM_DATA_BLOCKED}.
 *
 * A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it
 * wishes to send data, but is unable to do so due to stream-level flow
 * control.  This frame is analogous to DATA_BLOCKED (Section 19.12).
 *
 * An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only
 * stream MUST terminate the connection with error STREAM_STATE_ERROR.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class StreamDataBlockedFrameImpl implements Frame {

    private final FrameType type;

    public StreamDataBlockedFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.STREAM_DATA_BLOCKED ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.STREAM_DATA_BLOCKED.name()
            );
        }
    }

    /**
     * A variable-length integer indicating the stream that is
     * blocked due to flow control.
     */
    private StreamId streamId;

    /**
     * A variable-length integer indicating the offset
     * of the stream at which the blocking occurred.
     */
    private VariableLengthInteger maximumStreamData;

    @Override
    public boolean isValid() {
        return streamId != null
                && maximumStreamData != null;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += streamId.getValue().getEncodedLengthInBytes();
        sum += maximumStreamData.getEncodedLengthInBytes();
        return sum;
    }
}

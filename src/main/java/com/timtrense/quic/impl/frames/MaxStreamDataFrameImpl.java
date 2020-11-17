package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;

/**
 * max stream data frame.
 * existing known frames are : {@link FrameType#MAX_STREAM_DATA}.
 *
 * A MAX_STREAM_DATA frame (type=0x11) is used in flow control to inform
 * a peer of the maximum amount of data that can be sent on a stream.
 *
 * A MAX_STREAM_DATA frame can be sent for streams in the Recv state;
 * see Section 3.1.  Receiving a MAX_STREAM_DATA frame for a locally-
 * initiated stream that has not yet been created MUST be treated as a
 * connection error of type STREAM_STATE_ERROR.  An endpoint that
 * receives a MAX_STREAM_DATA frame for a receive-only stream MUST
 * terminate the connection with error STREAM_STATE_ERROR.
 *
 * When counting data toward this limit, an endpoint accounts for the
 * largest received offset of data that is sent or received on the
 * stream.  Loss or reordering can mean that the largest received offset
 * on a stream can be greater than the total size of data received on
 * that stream.  Receiving STREAM frames might not increase the largest
 * received offset.
 *
 * The data sent on a stream MUST NOT exceed the largest maximum stream
 * data value advertised by the receiver.  An endpoint MUST terminate a
 * connection with a FLOW_CONTROL_ERROR error if it receives more data
 * than the largest maximum stream data that it has sent for the
 * affected stream.  This includes violations of remembered limits in
 * Early Data; see Section 7.4.1.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class MaxStreamDataFrameImpl implements Frame {

    private final FrameType type;

    public MaxStreamDataFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.MAX_STREAM_DATA ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.MAX_STREAM_DATA.name()
            );
        }
    }

    /**
     * The stream ID of the stream that is affected encoded as a
     * variable-length integer.
     */
    private StreamId streamId;

    /**
     * A variable-length integer indicating the maximum
     * amount of data that can be sent on the entire connection, in units
     * of bytes.
     */
    private VariableLengthInteger maximumStreamData;

    @Override
    public boolean isValid() {
        return streamId != null
                && maximumStreamData != null;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += streamId.getValue().getEncodedLengthInBytes();
        sum += maximumStreamData.getEncodedLengthInBytes();
        return sum;
    }
}

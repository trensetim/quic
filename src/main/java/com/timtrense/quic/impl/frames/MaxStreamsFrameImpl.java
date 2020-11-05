package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;
import lombok.NonNull;

/**
 * max streams frame.
 * existing known frames are : {@link FrameGeneralType#MAX_STREAMS}.
 *
 * A MAX_STREAMS frame (type=0x12 or 0x13) inform the peer of the
 * cumulative number of streams of a given type it is permitted to open.
 * A MAX_STREAMS frame with a type of 0x12 applies to bidirectional
 * streams, and a MAX_STREAMS frame with a type of 0x13 applies to
 * unidirectional streams.
 *
 * Loss or reordering can cause a MAX_STREAMS frame to be received that
 * state a lower stream limit than an endpoint has previously received.
 * MAX_STREAMS frames that do not increase the stream limit MUST be
 * ignored.
 *
 * An endpoint MUST NOT open more streams than permitted by the current
 * stream limit set by its peer.  For instance, a server that receives a
 * unidirectional stream limit of 3 is permitted to open stream 3, 7,
 * and 11, but not stream 15.  An endpoint MUST terminate a connection
 * with a STREAM_LIMIT_ERROR error if a peer opens more streams than was
 * permitted.  This includes violations of remembered limits in Early
 * Data; see Section 7.4.1.
 *
 * Note that these frames (and the corresponding transport parameters)
 * do not describe the number of streams that can be opened
 * concurrently.  The limit includes streams that have been closed as
 * well as those that are open.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class MaxStreamsFrameImpl implements Frame {

    private final FrameType type;

    public MaxStreamsFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.MAX_STREAMS ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.MAX_STREAMS.name()
            );
        }
    }

    /**
     * A count of the cumulative number of streams of the
     * corresponding type that can be opened over the lifetime of the
     * connection.  This value cannot exceed 2^60, as it is not possible
     * to encode stream IDs larger than 2^62-1.  Receipt of a frame that
     * permits opening of a stream larger than this limit MUST be treated
     * as a FRAME_ENCODING_ERROR.
     */
    private VariableLengthInteger maximumStreams;

    @Override
    public boolean isValid() {
        return maximumStreams != null;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += maximumStreams.getEncodedLengthInBytes();
        return sum;
    }
}

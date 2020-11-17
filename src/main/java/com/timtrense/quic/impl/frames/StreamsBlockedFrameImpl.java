package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * streams blocked frame.
 * existing known frames are : {@link FrameGeneralType#STREAMS_BLOCKED}.
 *
 * A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when
 * it wishes to open a stream, but is unable to due to the maximum
 * stream limit set by its peer; see Section 19.11.  A STREAMS_BLOCKED
 * frame of type 0x16 is used to indicate reaching the bidirectional
 * stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to
 * indicate reaching the unidirectional stream limit.
 *
 * A STREAMS_BLOCKED frame does not open the stream, but informs the
 * peer that a new stream was needed and the stream limit prevented the
 * creation of the stream.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class StreamsBlockedFrameImpl implements Frame {

    private final FrameType type;

    public StreamsBlockedFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.STREAMS_BLOCKED ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.STREAMS_BLOCKED.name()
            );
        }
    }

    /**
     * A variable-length integer indicating the maximum
     * number of streams allowed at the time the frame was sent.  This
     * value cannot exceed 2^60, as it is not possible to encode stream
     * IDs larger than 2^62-1.  Receipt of a frame that encodes a larger
     * stream ID MUST be treated as a STREAM_LIMIT_ERROR or a
     * FRAME_ENCODING_ERROR.
     */
    private VariableLengthInteger maximumStreams;

    @Override
    public boolean isValid() {
        return maximumStreams != null;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += maximumStreams.getEncodedLengthInBytes();
        return sum;
    }
}

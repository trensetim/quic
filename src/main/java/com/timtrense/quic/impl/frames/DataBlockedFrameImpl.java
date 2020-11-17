package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * data blocked frame.
 * existing known frames are : {@link FrameType#DATA_BLOCKED}.
 *
 * A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes
 * to send data, but is unable to do so due to connection-level flow
 * control; see Section 4.  DATA_BLOCKED frames can be used as input to
 * tuning of flow control algorithms; see Section 4.2.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class DataBlockedFrameImpl implements Frame {

    private final FrameType type;

    public DataBlockedFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.DATA_BLOCKED ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.DATA_BLOCKED.name()
            );
        }
    }

    /**
     * A variable-length integer indicating the connection-
     * level limit at which blocking occurred.
     */
    private VariableLengthInteger maximumData;

    @Override
    public boolean isValid() {
        return maximumData != null;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += maximumData.getEncodedLengthInBytes();
        return sum;
    }
}

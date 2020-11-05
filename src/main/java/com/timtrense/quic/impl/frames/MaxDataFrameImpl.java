package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;
import lombok.NonNull;

/**
 * max data frame.
 * existing known frames are : {@link FrameType#MAX_DATA}.
 *
 * A MAX_DATA frame (type=0x10) is used in flow control to inform the
 * peer of the maximum amount of data that can be sent on the connection
 * as a whole.
 *
 * All data sent in STREAM frames counts toward this limit.  The sum of
 * the final sizes on all streams - including streams in terminal states
 * - MUST NOT exceed the value advertised by a receiver.  An endpoint
 * MUST terminate a connection with a FLOW_CONTROL_ERROR error if it
 * receives more data than the maximum data value that it has sent.
 * This includes violations of remembered limits in Early Data; see
 * Section 7.4.1.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class MaxDataFrameImpl implements Frame {

    private final FrameType type;

    public MaxDataFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.MAX_DATA ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.MAX_DATA.name()
            );
        }
    }

    /**
     * A variable-length integer indicating the maximum
     * amount of data that can be sent on the entire connection, in units
     * of bytes.
     */
    private VariableLengthInteger maximumData;

    @Override
    public boolean isValid() {
        return maximumData != null;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += maximumData.getEncodedLengthInBytes();
        return sum;
    }
}

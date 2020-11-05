package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;
import lombok.NonNull;

/**
 * reset stream frame.
 * existing known frames are : {@link FrameType#RESET_STREAM}
 *
 * An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly
 * terminate the sending part of a stream.
 *
 * After sending a RESET_STREAM, an endpoint ceases transmission and
 * retransmission of STREAM frames on the identified stream.  A receiver
 * of RESET_STREAM can discard any data that it already received on that
 * stream.
 *
 * An endpoint that receives a RESET_STREAM frame for a send-only stream
 * MUST terminate the connection with error STREAM_STATE_ERROR.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.4">QUIC Spec/Section 19.4</a>
 */
@Data
public class ResetStreamFrameImpl implements Frame {

    private final FrameType type;

    public ResetStreamFrameImpl( @NonNull FrameType type ) {
        this.type = type;
        if ( type.getGeneralType() != FrameGeneralType.RESET_STREAM ) {
            throw new IllegalArgumentException(
                    "Cannot build an ResetStreamFrame with FrameGeneralType other than "
                            + FrameGeneralType.RESET_STREAM.name()
            );
        }
    }

    /**
     * A variable-length integer encoding of the Stream ID of
     * the stream being terminated
     */
    private StreamId streamId;

    /**
     * A variable-length integer
     * containing the application protocol error code (see Section 20.2)
     * that indicates why the stream is being closed
     */
    private VariableLengthInteger applicationProtocolErrorCode;

    /**
     * A variable-length integer indicating the final size of
     * the stream by the RESET_STREAM sender, in unit of bytes; see
     * Section 4.5
     */
    private VariableLengthInteger finalSize;

    @Override
    public boolean isValid() {
        return streamId != null
                && finalSize != null
                && applicationProtocolErrorCode != null;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += streamId.getValue().getEncodedLengthInBytes();
        sum += applicationProtocolErrorCode.getEncodedLengthInBytes();
        sum += finalSize.getEncodedLengthInBytes();
        return sum;
    }
}

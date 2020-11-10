package com.timtrense.quic.impl.frames;

import lombok.Data;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.base.VariableLengthIntegerEncoder;

/**
 * stream frame.
 * existing known frames are : {@link FrameType#STREAM} to {@link FrameType#STREAM_OFF_LEN_FIN}
 *
 * STREAM frames implicitly create a stream and carry stream data.  The
 * STREAM frame Type field takes the form 0b00001XXX (or the set of
 * values from 0x08 to 0x0f).  The three low-order bits of the frame
 * type determine the fields that are present in the frame:
 *
 * <ul>
 * <li>
 *     The OFF bit (0x04) in the frame type is set to indicate that there
 *      is an Offset field present.  When set to 1, the Offset field is
 *      present.  When set to 0, the Offset field is absent and the Stream
 *      Data starts at an offset of 0 (that is, the frame contains the
 *      first bytes of the stream, or the end of a stream that includes no
 *      data).
 * </li>
 * <li>
 *     The LEN bit (0x02) in the frame type is set to indicate that there
 *      is a Length field present.  If this bit is set to 0, the Length
 *      field is absent and the Stream Data field extends to the end of
 *      the packet.  If this bit is set to 1, the Length field is present.
 * </li>
 * <li>
 *     The FIN bit (0x01) indicates that the frame marks the end of the
 *      stream.  The final size of the stream is the sum of the offset and
 *      the length of this frame.
 * </li>
 * </ul>
 *
 * An endpoint MUST terminate the connection with error
 * STREAM_STATE_ERROR if it receives a STREAM frame for a locally-
 * initiated stream that has not yet been created, or for a send-only
 * stream.
 *
 * When a Stream Data field has a length of 0, the offset in the STREAM
 * frame is the offset of the next byte that would be sent.
 *
 * The first byte in the stream has an offset of 0.  The largest offset
 * delivered on a stream - the sum of the offset and data length -
 * cannot exceed 2^62-1, as it is not possible to provide flow control
 * credit for that data.  Receipt of a frame that exceeds this limit
 * MUST be treated as a connection error of type FRAME_ENCODING_ERROR or
 * FLOW_CONTROL_ERROR.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class StreamFrameImpl implements Frame {

    private final FrameType type;

    public StreamFrameImpl( FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.STREAM ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.STREAM.name()
            );
        }
    }

    /**
     * A variable-length integer indicating the stream ID of the
     * stream; see Section 2.1.
     */
    private StreamId streamId;
    /**
     * A variable-length integer specifying the byte offset in the
     * stream for the data in this STREAM frame.  This field is present
     * when the OFF bit is set to 1.  When the Offset field is absent,
     * the offset is 0.
     */
    private VariableLengthInteger offset;
    /**
     * A variable-length integer specifying the length of the
     * Stream Data field in this STREAM frame.  This field is present
     * when the LEN bit is set to 1.  When the LEN bit is set to 0, the
     * Stream Data field consumes all the remaining bytes in the packet.
     */
    private VariableLengthInteger length;
    /**
     * The bytes from the designated stream to be delivered.
     */
    private byte[] data;

    /**
     * checks whether the FIN-Bit is set, thus making this the last frame of data for the associated stream
     *
     * @return true if the FIN-Bit is set
     */
    public boolean isFinBitSet() {
        return ( type.getLongValue() & 0x01 ) == 0x01;
    }

    /**
     * checks whether the LEN-Bit is set, thus expecting this frame to have a given length
     *
     * @return true if the LEN-Bit is set
     */
    public boolean isLengthBitSet() {
        return ( type.getLongValue() & 0x02 ) == 0x02;
    }

    /**
     * checks whether the OFF-Bit is set, thus expecting this frame to have a given offset
     *
     * @return true if the OFF-Bit is set
     */
    public boolean isOffsetBitSet() {
        return ( type.getLongValue() & 0x04 ) == 0x04;
    }

    @Override
    public boolean isValid() {
        if ( streamId == null ) {
            return false;
        }
        if ( isLengthBitSet() && length == null ) {
            return false;
        }
        if ( isOffsetBitSet() && offset == null ) {
            return false;
        }
        if ( length != null && length.longValue() != data.length ) {
            return false;
        }
        //noinspection RedundantIfStatement
        if ( offset != null
                && length != null
                && VariableLengthIntegerEncoder.getLengthInBytes(
                offset.longValue() + length.longValue() ) == 0 ) {
            // QUOTE: The largest offset
            //   delivered on a stream - the sum of the offset and data length -
            //   cannot exceed 2^62-1, as it is not possible to provide flow control
            //   credit for that data
            return false;
        }
        return true;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += streamId.getValue().getEncodedLengthInBytes();
        if ( length != null ) {
            sum += length.getEncodedLengthInBytes();
            sum += length.getValue();
        }
        else {
            sum += data.length;
        }
        if ( offset != null ) {
            sum += offset.getEncodedLengthInBytes();
        }
        return sum;
    }
}

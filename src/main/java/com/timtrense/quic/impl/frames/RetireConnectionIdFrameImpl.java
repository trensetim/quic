package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * retire connection id frame.
 * existing known frames are : {@link FrameType#RETIRE_CONNECTION_ID}.
 *
 * An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to
 * indicate that it will no longer use a connection ID that was issued
 * by its peer.  This may include the connection ID provided during the
 * handshake.  Sending a RETIRE_CONNECTION_ID frame also serves as a
 * request to the peer to send additional connection IDs for future use;
 * see Section 5.1.  New connection IDs can be delivered to a peer using
 * the NEW_CONNECTION_ID frame (Section 19.15).
 *
 * Retiring a connection ID invalidates the stateless reset token
 * associated with that connection ID.
 *
 * Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
 * greater than any previously sent to the peer MUST be treated as a
 * connection error of type PROTOCOL_VIOLATION.
 *
 * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST
 * NOT refer to the Destination Connection ID field of the packet in
 * which the frame is contained.  The peer MAY treat this as a
 * connection error of type PROTOCOL_VIOLATION.
 *
 * An endpoint cannot send this frame if it was provided with a zero-
 * length connection ID by its peer.  An endpoint that provides a zero-
 * length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID
 * frame as a connection error of type PROTOCOL_VIOLATION.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class RetireConnectionIdFrameImpl implements Frame {

    private final FrameType type;

    public RetireConnectionIdFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.RETIRE_CONNECTION_ID ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.RETIRE_CONNECTION_ID.name()
            );
        }
    }

    /**
     * The sequence number of the connection ID being
     * retired; see Section 5.1.2.
     */
    private VariableLengthInteger sequenceNumber;

    @Override
    public boolean isValid() {
        return sequenceNumber != null;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += sequenceNumber.getEncodedLengthInBytes();
        return sum;
    }
}

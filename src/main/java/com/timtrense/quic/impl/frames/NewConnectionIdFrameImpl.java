package com.timtrense.quic.impl.frames;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.StatelessResetToken;
import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;
import lombok.NonNull;

/**
 * new connection id frame.
 * existing known frames are : {@link FrameType#NEW_CONNECTION_ID}.
 *
 * An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide
 * its peer with alternative connection IDs that can be used to break
 * linkability when migrating connections; see Section 9.5.
 *
 * An endpoint MUST NOT send this frame if it currently requires that
 * its peer send packets with a zero-length Destination Connection ID.
 * Changing the length of a connection ID to or from zero-length makes
 * it difficult to identify when the value of the connection ID changed.
 * An endpoint that is sending packets with a zero-length Destination
 * Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a
 * connection error of type PROTOCOL_VIOLATION.
 *
 * Transmission errors, timeouts and retransmissions might cause the
 * same NEW_CONNECTION_ID frame to be received multiple times.  Receipt
 * of the same frame multiple times MUST NOT be treated as a connection
 * error.  A receiver can use the sequence number supplied in the
 * NEW_CONNECTION_ID frame to handle receiving the same
 * NEW_CONNECTION_ID frame multiple times.
 *
 * If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
 * previously issued connection ID with a different Stateless Reset
 * Token or a different sequence number, or if a sequence number is used
 * for different connection IDs, the endpoint MAY treat that receipt as
 * a connection error of type PROTOCOL_VIOLATION.
 *
 * The Retire Prior To field applies to connection IDs established
 * during connection setup and the preferred_address transport
 * parameter; see Section 5.1.2.  The Retire Prior To field MUST be less
 * than or equal to the Sequence Number field.  Receiving a value
 * greater than the Sequence Number MUST be treated as a connection
 * error of type FRAME_ENCODING_ERROR.
 *
 * Once a sender indicates a Retire Prior To value, smaller values sent
 * in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
 * MUST ignore any Retire Prior To fields that do not increase the
 * largest received Retire Prior To value.
 *
 * An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
 * number smaller than the Retire Prior To field of a previously
 * received NEW_CONNECTION_ID frame MUST send a corresponding
 * RETIRE_CONNECTION_ID frame that retires the newly received connection
 * ID, unless it has already done so for that sequence number.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class NewConnectionIdFrameImpl implements Frame {

    private final FrameType type;

    public NewConnectionIdFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.NEW_CONNECTION_ID ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.NEW_CONNECTION_ID.name()
            );
        }
    }

    /**
     * The sequence number assigned to the connection ID
     * by the sender, encoded as a variable-length integer; see
     * Section 5.1.1.
     */
    private VariableLengthInteger sequenceNumber;
    /**
     * A variable-length integer indicating which connection IDs
     * should be retired; see Section 5.1.2.
     */
    private VariableLengthInteger retirePriorTo;
    /**
     * An 8-bit unsigned integer containing the length of the
     * connection ID.  Values less than 1 and greater than 20 are invalid
     * and MUST be treated as a connection error of type
     * FRAME_ENCODING_ERROR.
     */
    private int length;
    /**
     * A connection ID of the specified length.
     */
    private ConnectionId connectionId;
    /**
     * A 128-bit value that will be used for a
     * stateless reset when the associated connection ID is used; see
     * Section 10.3.
     */
    private StatelessResetToken statelessResetToken;

    @Override
    public boolean isValid() {
        return sequenceNumber != null
                && retirePriorTo != null
                && length > 0 && length < 21
                && connectionId != null
//                && statelessResetToken != null //TODO: does the packet need to have that?
                ;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += sequenceNumber.getEncodedLengthInBytes();
        sum += retirePriorTo.getEncodedLengthInBytes();
        sum += 1 + 16; // length + stateless reset token
        sum += length; // connectionId
        return sum;
    }
}

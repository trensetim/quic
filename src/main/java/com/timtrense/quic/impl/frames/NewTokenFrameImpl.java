package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * new token frame.
 * existing known frames are : {@link FrameType#NEW_TOKEN}.
 *
 * A server sends a NEW_TOKEN frame (type=0x07) to provide the client
 * with a token to send in the header of an Initial packet for a future
 * connection.
 *
 * An endpoint might receive multiple NEW_TOKEN frames that contain the
 * same token value if packets containing the frame are incorrectly
 * determined to be lost.  Endpoints are responsible for discarding
 * duplicate values, which might be used to link connection attempts;
 * see Section 8.1.3.
 *
 * Clients MUST NOT send NEW_TOKEN frames. Servers MUST treat receipt
 * of a NEW_TOKEN frame as a connection error of type
 * PROTOCOL_VIOLATION.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class NewTokenFrameImpl implements Frame {

    private final FrameType type;

    public NewTokenFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.NEW_TOKEN ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.NEW_TOKEN.name()
            );
        }
    }

    /**
     * A variable-length integer specifying the length of the
     * token in bytes.
     */
    private VariableLengthInteger tokenLength;
    /**
     * An opaque blob that the client may use with a future Initial
     * packet.  The token MUST NOT be empty.  An endpoint MUST treat
     * receipt of a NEW_TOKEN frame with an empty Token field as a
     * connection error of type FRAME_ENCODING_ERROR.
     */
    private byte[] token;

    @Override
    public boolean isValid() {
        return tokenLength != null
                && token != null
                && token.length > 0
                && tokenLength.longValue() == token.length
                ;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += tokenLength.getEncodedLengthInBytes();
        sum += tokenLength.getValue();
        return sum;
    }
}

package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import lombok.Data;
import lombok.NonNull;

/**
 * path response frame.
 * existing known frames are : {@link FrameType#PATH_RESPONSE}.
 *
 * A PATH_RESPONSE frame (type=0x1b) is sent in response to a
 * PATH_CHALLENGE frame.
 *
 * PATH_RESPONSE frames are formatted as shown in Figure 42, which is
 * identical to the PATH_CHALLENGE frame (Section 19.17).
 *
 * If the content of a PATH_RESPONSE frame does not match the content of
 * a PATH_CHALLENGE frame previously sent by the endpoint, the endpoint
 * MAY generate a connection error of type PROTOCOL_VIOLATION.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class PathResponseFrameImpl implements Frame {

    private final FrameType type;

    public PathResponseFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.PATH_RESPONSE ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.PATH_RESPONSE.name()
            );
        }
    }

    /**
     * This 8-byte field contains arbitrary data.
     */
    private byte[] data;

    @Override
    public boolean isValid() {
        return data != null
                && data.length == 8
                ;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        /*
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += 8; // data.length == 8 by protocol specification
        return sum;
        */
        return 9; // 8 (data.length) + 1 (encoded length of type PATH_RESPONSE which is 0x1b)
    }
}

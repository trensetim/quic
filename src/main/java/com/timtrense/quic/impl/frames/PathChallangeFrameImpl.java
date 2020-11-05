package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import lombok.Data;
import lombok.NonNull;

/**
 * path challange frame.
 * existing known frames are : {@link FrameType#PATH_CHALLENGE}.
 *
 * Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check
 * reachability to the peer and for path validation during connection
 * migration.
 *
 * Including 64 bits of entropy in a PATH_CHALLENGE frame ensures that
 * it is easier to receive the packet than it is to guess the value
 * correctly.
 *
 * The recipient of this frame MUST generate a PATH_RESPONSE frame
 * (Section 19.18) containing the same Data.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class PathChallangeFrameImpl implements Frame {

    private final FrameType type;

    public PathChallangeFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.PATH_CHALLENGE ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.PATH_CHALLENGE.name()
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
        return 9; // 8 (data.length) + 1 (encoded length of type PATH_CHALLENGE which is 0x1a)
    }
}

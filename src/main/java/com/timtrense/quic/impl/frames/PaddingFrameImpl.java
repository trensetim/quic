package com.timtrense.quic.impl.frames;

import lombok.Data;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;

/**
 * padding frame.
 * existing known frames are : {@link FrameType#PADDING}
 * <p/>
 * A PADDING frame (type=0x00) has no semantic value.  PADDING frames
 * can be used to increase the size of a packet.  Padding can be used to
 * increase an initial client packet to the minimum required size, or to
 * provide protection against traffic analysis for protected packets.
 * <p/>
 * PADDING frames are formatted as shown in Figure 23, which shows that
 * PADDING frames have no content.  That is, a PADDING frame consists of
 * the single byte that identifies the frame as a PADDING frame.
 * <p/>
 * <b>Note:</b> Implementations should use {@link MultiPaddingFrameImpl}
 * in order to not need to instantiate absurd amounts of {@link PaddingFrameImpl}
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class PaddingFrameImpl implements Frame {

    private final FrameType type;

    public PaddingFrameImpl( FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.PADDING ) {
            throw new IllegalArgumentException(
                    "Cannot build a PaddingFrame with FrameGeneralType other than "
                            + FrameGeneralType.PADDING.name()
            );
        }
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public long getFrameLength() {
        // this will always be 1, because type.getValue() == 0
        // return type.getValue().getEncodedLengthInBytes();
        return 1;
    }
}

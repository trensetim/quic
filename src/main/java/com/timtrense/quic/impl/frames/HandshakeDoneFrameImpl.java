package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;

/**
 * handshake done frame.
 * existing known frames are : {@link FrameType#HANDSHAKE_DONE}.
 *
 * The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal
 * confirmation of the handshake to the client.
 *
 * HANDSHAKE_DONE frames are formatted as shown in Figure 44, which
 * shows that HANDSHAKE_DONE frames have no content.
 *
 * A HANDSHAKE_DONE frame can only be sent by the server.  Servers MUST
 * NOT send a HANDSHAKE_DONE frame before completing the handshake.  A
 * server MUST treat receipt of a HANDSHAKE_DONE frame as a connection
 * error of type PROTOCOL_VIOLATION.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class HandshakeDoneFrameImpl implements Frame {

    private final FrameType type;

    public HandshakeDoneFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.HANDSHAKE_DONE ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.HANDSHAKE_DONE.name()
            );
        }
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public long getFrameLength() {
        return type.getValue().getEncodedLengthInBytes();
    }
}

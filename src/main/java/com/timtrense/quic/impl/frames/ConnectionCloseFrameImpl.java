package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;
import lombok.Data;
import lombok.NonNull;

import java.nio.charset.StandardCharsets;

/**
 * connection close frame.
 * existing known frames are : {@link FrameGeneralType#CONNECTION_CLOSE}.
 *
 * An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) to
 * notify its peer that the connection is being closed.  The
 * CONNECTION_CLOSE with a frame type of 0x1c is used to signal errors
 * at only the QUIC layer, or the absence of errors (with the NO_ERROR
 * code).  The CONNECTION_CLOSE frame with a type of 0x1d is used to
 * signal an error with the application that uses QUIC.
 *
 * If there are open streams that have not been explicitly closed, they
 * are implicitly closed when the connection is closed.
 *
 * The application-specific variant of CONNECTION_CLOSE (type 0x1d) can
 * only be sent using 0-RTT or 1-RTT packets; see Section 12.5.  When an
 * application wishes to abandon a connection during the handshake, an
 * endpoint can send a CONNECTION_CLOSE frame (type 0x1c) with an error
 * code of APPLICATION_ERROR in an Initial or a Handshake packet.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class ConnectionCloseFrameImpl implements Frame {

    private final FrameType type;

    public ConnectionCloseFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.CONNECTION_CLOSE ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.CONNECTION_CLOSE.name()
            );
        }
    }

    /**
     * A variable-length integer error code that indicates the
     * reason for closing this connection.  A CONNECTION_CLOSE frame of
     * type 0x1c uses codes from the space defined in Section 20.1.  A
     * CONNECTION_CLOSE frame of type 0x1d uses codes from the
     * application protocol error code space; see Section 20.2.
     */
    private VariableLengthInteger errorCode;

    /**
     * A variable-length integer encoding the type of frame
     * that triggered the error.  A value of 0 (equivalent to the mention
     * of the PADDING frame) is used when the frame type is unknown.  The
     * application-specific variant of CONNECTION_CLOSE (type 0x1d) does
     * not include this field.
     */
    private VariableLengthInteger frameType;

    /**
     * A variable-length integer specifying the
     * length of the reason phrase in bytes.  Because a CONNECTION_CLOSE
     * frame cannot be split between packets, any limits on packet size
     * will also limit the space available for a reason phrase.
     */
    private VariableLengthInteger reasonPhraseLength;

    /**
     * A human-readable explanation for why the connection
     * was closed.  This can be zero length if the sender chooses not to
     * give details beyond the Error Code.  This SHOULD be a UTF-8
     * encoded string [RFC3629].
     */
    private byte[] reasonPhrase;

    /**
     * checks whether the {@link FrameType} least significant bit is set, indicating that this frame MUST hold a
     * frameType
     *
     * @return true if the frame type bit is set
     */
    public boolean hasFrameTypeBitSet() {
        return ( type.getLongValue() & 0x01 ) == 0x01;
    }

    /**
     * @param reasonPhrase a {@link StandardCharsets#UTF_8 UTF-8} encoded string
     */
    public void setReasonPhrase( byte[] reasonPhrase ) {
        this.reasonPhrase = reasonPhrase;
    }

    /**
     * {@link StandardCharsets#UTF_8 UTF-8}-encodes the given string and sets the encoded bytes as the reason phrase
     *
     * @param reasonPhrase a {@link StandardCharsets#UTF_8 UTF-8}-encodable {@link #reasonPhrase}
     */
    public void setReasonPhrase( @NonNull String reasonPhrase ) {
        this.reasonPhrase = reasonPhrase.getBytes( StandardCharsets.UTF_8 );
    }

    @Override
    public boolean isValid() {
        return errorCode != null
                && ( hasFrameTypeBitSet() == ( frameType != null ) )
                && reasonPhraseLength != null
                && reasonPhrase != null
                && reasonPhraseLength.longValue() == reasonPhrase.length
                ;
    }

    @Override
    public long getFrameLength() throws NullPointerException {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += errorCode.getEncodedLengthInBytes();
        if ( frameType != null ) {
            sum += frameType.getEncodedLengthInBytes();
        }
        sum += reasonPhraseLength.getEncodedLengthInBytes();
        sum += reasonPhraseLength.getValue();
        return sum;
    }
}

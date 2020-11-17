package com.timtrense.quic.impl.frames;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * crypto frame.
 * existing known frames are : {@link FrameType#CRYPTO}.
 *
 * A CRYPTO frame (type=0x06) is used to transmit cryptographic
 * handshake messages.  It can be sent in all packet types except 0-RTT.
 * The CRYPTO frame offers the cryptographic protocol an in-order stream
 * of bytes.  CRYPTO frames are functionally identical to STREAM frames,
 * except that they do not bear a stream identifier; they are not flow
 * controlled; and they do not carry markers for optional offset,
 * optional length, and the end of the stream.
 *
 * There is a separate flow of cryptographic handshake data in each
 * encryption level, each of which starts at an offset of 0.  This
 * implies that each encryption level is treated as a separate CRYPTO
 * stream of data.
 *
 * The largest offset delivered on a stream - the sum of the offset and
 * data length - cannot exceed 2^62-1.  Receipt of a frame that exceeds
 * this limit MUST be treated as a connection error of type
 * FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.
 *
 * Unlike STREAM frames, which include a Stream ID indicating to which
 * stream the data belongs, the CRYPTO frame carries data for a single
 * stream per encryption level.  The stream does not have an explicit
 * end, so CRYPTO frames do not have a FIN bit.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.6">QUIC Spec/Section 19.6</a>
 */
@Data
public class CryptoFrameImpl implements Frame {

    private final FrameType type;

    /**
     * A variable-length integer specifying the byte offset in the
     * stream for the data in this CRYPTO frame
     */
    private VariableLengthInteger offset;
    /**
     * A variable-length integer specifying the length of the
     * Crypto Data field in this CRYPTO frame
     */
    private VariableLengthInteger length;
    /**
     * The cryptographic message data
     */
    private byte[] cryptoData;

    public CryptoFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.CRYPTO ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.CRYPTO.name()
            );
        }
    }

    @Override
    public boolean isValid() {
        return offset != null
                && length != null
                && cryptoData != null
                && cryptoData.length > 0
                && length.longValue() == cryptoData.length
                ;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += offset.getEncodedLengthInBytes();
        sum += length.getEncodedLengthInBytes();
        sum += length.getValue();
        return sum;
    }
}

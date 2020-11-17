package com.timtrense.quic;

/**
 * payload component of a packet.
 *
 * As described in Section 12.4, packets contain one or more frames.
 * This section describes the format and semantics of the core QUIC
 * frame types.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12.4">QUIC Spec/Section 12.4</a>
 */
public interface Frame {

    /**
     * @return the type of this frame
     */
    FrameType getType();

    /**
     * @return true if all necessary data for that frame is present
     */
    boolean isValid();

    /**
     * Attention: this function may return a valid number that is not actually accurate
     * IF AND ONLY IF <code>{@link #isValid()} == false</code>
     *
     * @return the length of this frame in bytes or -1 if the frame is either invalid or of unknown length
     * @throws NullPointerException if the frame contains required fields with null value
     */
    long getFrameLength();
}

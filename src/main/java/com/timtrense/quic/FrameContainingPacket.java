package com.timtrense.quic;

import java.util.List;

/**
 * UDP datagram payload.
 *
 * See {@link Packet} for details on packets in general.
 *
 * This class gives an abstraction for packets actually containing {@link Frame Frames} as payload,
 * because not all packets do.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12">QUIC Spec/Section 12</a>
 */
public interface FrameContainingPacket extends Packet {

    /**
     * The payload of QUIC packets, after removing packet protection,
     * consists of a sequence of complete frames, as shown in Figure 11.
     * Version Negotiation, Stateless Reset, and Retry packets do not
     * contain frames.
     *
     * The payload of a packet that contains frames MUST contain at least
     * one frame, and MAY contain multiple frames and multiple frame types.
     * Frames always fit within a single QUIC packet and cannot span
     * multiple packets.
     *
     * Each frame begins with a Frame Type, indicating its type, followed by
     * additional type-dependent fields:
     *
     * @return all contained frames
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-12.4">QUIC Spec/Section 12.4</a>
     */
    List<Frame> getPayload();

    /**
     * Attention: this function may return a valid number that is not actually accurate
     * IF AND ONLY IF <code>{@link Frame#isValid()} == false</code> for ANY contained frame
     *
     * @return the sum of the lengths of this packets payload in bytes or an invalid number if ANY frame is invalid
     * @throws NullPointerException if any of the packets payload frames contain required fields with null value
     */
    default long getLongPayloadLength() throws NullPointerException {
        long sum = 0;
        List<Frame> payload = getPayload();
        if ( payload != null ) {
            for ( Frame frame : payload ) {
                sum += frame.getFrameLength();
            }
        }
        return sum;
    }

    /**
     * Attention: this function may return a valid number that is not actually accurate
     * IF AND ONLY IF <code>{@link Frame#isValid()} == false</code> for ANY contained frame
     *
     * @return the sum of the lengths of this packets payload in bytes or an invalid number if ANY frame is invalid
     * @throws NullPointerException     if any of the packets payload frames contain required fields with null value
     * @throws IllegalArgumentException if the computed length cannot be expressed as a {@link VariableLengthInteger}
     */
    default VariableLengthInteger getPayloadLength() throws NullPointerException, IllegalArgumentException {
        return new VariableLengthInteger( getLongPayloadLength() );
    }

    /**
     * Checks the header of this packet but AND whether all packed frames are valid too.
     *
     * @return true if all necessary data for that packet is present AND the payload is valid
     */
    default boolean isDeepValid() {
        if ( !isPacketValid() ) {
            return false;
        }
        for ( Frame f : getPayload() ) {
            if ( f == null || !f.isValid() ) {
                return false;
            }
        }
        return true;
    }
}

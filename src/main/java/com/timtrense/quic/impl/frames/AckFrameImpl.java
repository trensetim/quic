package com.timtrense.quic.impl.frames;

import java.util.LinkedList;
import java.util.List;
import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.AckRange;
import com.timtrense.quic.EcnCount;
import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameGeneralType;
import com.timtrense.quic.FrameType;
import com.timtrense.quic.VariableLengthInteger;

/**
 * acknowledgement frame.
 * existing known frames are : {@link FrameType#ACK} and {@link FrameType#ACK_WITH_ECN}.
 *
 * Receivers send ACK frames (types 0x02 and 0x03) to inform senders of
 * packets they have received and processed.  The ACK frame contains one
 * or more ACK Ranges.  ACK Ranges identify acknowledged packets.  If
 * the frame type is 0x03, ACK frames also contain the sum of QUIC
 * packets with associated ECN marks received on the connection up until
 * this point.  QUIC implementations MUST properly handle both types
 * and, if they have enabled ECN for packets they send, they SHOULD use
 * the information in the ECN section to manage their congestion state.
 *
 * QUIC acknowledgements are irrevocable.  Once acknowledged, a packet
 * remains acknowledged, even if it does not appear in a future ACK
 * frame.  This is unlike reneging for TCP SACKs ([RFC2018]).
 *
 * Packets from different packet number spaces can be identified using
 * the same numeric value.  An acknowledgment for a packet needs to
 * indicate both a packet number and a packet number space.  This is
 * accomplished by having each ACK frame only acknowledge packet numbers
 * in the same space as the packet in which the ACK frame is contained.
 *
 * Version Negotiation and Retry packets cannot be acknowledged because
 * they do not contain a packet number.  Rather than relying on ACK
 * frames, these packets are implicitly acknowledged by the next Initial
 * packet sent by the client.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3">QUIC Spec/Section 19.3</a>
 */
@Data
public class AckFrameImpl implements Frame {

    private final FrameType type;

    public AckFrameImpl( @NonNull FrameType frameType ) {
        this.type = frameType;
        if ( type.getGeneralType() != FrameGeneralType.ACK ) {
            throw new IllegalArgumentException(
                    "Cannot build an AckFrame with FrameGeneralType other than "
                            + FrameGeneralType.ACK.name()
            );
        }
    }

    /**
     * A variable-length integer representing the
     * largest packet number the peer is acknowledging; this is usually
     * the largest packet number that the peer has received prior to
     * generating the ACK frame.  Unlike the packet number in the QUIC
     * long or short header, the value in an ACK frame is not truncated.
     */
    private VariableLengthInteger largestAcknowledged;
    /**
     * A variable-length integer indicating the number of
     * contiguous packets preceding the Largest Acknowledged that are
     * being acknowledged.  The First ACK Range is encoded as an ACK
     * Range; see Section 19.3.1 starting from the Largest Acknowledged.
     * That is, the smallest packet acknowledged in the range is
     * determined by subtracting the First ACK Range value from the
     * Largest Acknowledged.
     */
    private VariableLengthInteger firstAcknowledgedRange;
    /**
     * A variable-length integer encoding the acknowledgement
     * delay in microseconds; see Section 13.2.5.  It is decoded by
     * multiplying the value in the field by 2 to the power of the
     * ack_delay_exponent transport parameter sent by the sender of the
     * ACK frame; see Section 18.2.  Compared to simply expressing the
     * delay as an integer, this encoding allows for a larger range of
     * values within the same number of bytes, at the cost of lower
     * resolution
     */
    private VariableLengthInteger delay;

    /**
     * Contains additional ranges of packets that are
     * alternately not acknowledged (Gap) and acknowledged (ACK Range);
     * see Section 19.3.1.
     */
    private final List<AckRange> ranges = new LinkedList<>();
    private List<EcnCount> ecnCounts = null;

    /**
     * ACK Range Count:  A variable-length integer specifying the number of
     * Gap and ACK Range fields in the frame.
     *
     * @return number of Gap and ACK Range fields in the frame (not including the first one)
     */
    public VariableLengthInteger getRangeCount() {
        return new VariableLengthInteger( ranges.size() );
    }

    /**
     * ACK Range Count:  A variable-length integer specifying the number of
     * Gap and ACK Range fields in the frame.
     *
     * @return number of Gap and ACK Range fields in the frame (not including the first one)
     */
    public long getLongRangeCount() {
        return ranges.size();
    }

    /**
     * checks whether the ECN-Bit is set, thus making this the last have ECN-Counts
     *
     * @return true if the ECN-Bit is set
     */
    public boolean isEcnBitSet() {
        return ( type.getLongValue() & 0x01 ) == 0x01;
    }

    @Override
    public boolean isValid() {
        return largestAcknowledged != null
                && firstAcknowledgedRange != null
                && delay != null
                &&
                (
                        isEcnBitSet()
                                ? ( ecnCounts != null && !ecnCounts.isEmpty() )
                                : ( ecnCounts == null || ecnCounts.isEmpty() )
                )
                ;
    }

    @Override
    public long getFrameLength() {
        long sum = type.getValue().getEncodedLengthInBytes();
        sum += largestAcknowledged.getEncodedLengthInBytes();
        sum += delay.getEncodedLengthInBytes();
        sum += getRangeCount().getEncodedLengthInBytes();
        sum += firstAcknowledgedRange.getEncodedLengthInBytes();
        for ( AckRange r : ranges ) {
            sum += r.getGap().getEncodedLengthInBytes();
            sum += r.getLength().getEncodedLengthInBytes();
        }
        if ( ecnCounts != null ) {
            for ( EcnCount e : ecnCounts ) {
                sum += e.getEct0Count().getEncodedLengthInBytes();
                sum += e.getEct1Count().getEncodedLengthInBytes();
                sum += e.getEcnCeCount().getEncodedLengthInBytes();
            }
        }
        return sum;
    }
}

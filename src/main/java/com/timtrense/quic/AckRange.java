package com.timtrense.quic;

/**
 * Each ACK Range consists of alternating Gap and ACK Range values in
 * descending packet number order.  ACK Ranges can be repeated.  The
 * number of Gap and ACK Range values is determined by the ACK Range
 * Count field; one of each value is present for each value in the ACK
 * Range Count field.
 *
 * Gap and ACK Range value use a relative integer encoding for
 * efficiency.  Though each encoded value is positive, the values are
 * subtracted, so that each ACK Range describes progressively lower-
 * numbered packets.
 *
 * Each ACK Range acknowledges a contiguous range of packets by
 * indicating the number of acknowledged packets that precede the
 * largest packet number in that range.  A value of zero indicates that
 * only the largest packet number is acknowledged.  Larger ACK Range
 * values indicate a larger range, with corresponding lower values for
 * the smallest packet number in the range.  Thus, given a largest
 * packet number for the range, the smallest value is determined by the
 * formula:
 *
 * <code>smallest = largest - ack_range</code>
 *
 * An ACK Range acknowledges all packets between the smallest packet
 * number and the largest, inclusive.
 *
 * The largest value for an ACK Range is determined by cumulatively
 * subtracting the size of all preceding ACK Ranges and Gaps.
 *
 * Each Gap indicates a range of packets that are not being
 * acknowledged.  The number of packets in the gap is one higher than
 * the encoded value of the Gap field.
 *
 * The value of the Gap field establishes the largest packet number
 * value for the subsequent ACK Range using the following formula:
 *
 * <code>largest = previous_smallest - gap - 2</code>
 *
 * If any computed packet number is negative, an endpoint MUST generate
 * a connection error of type FRAME_ENCODING_ERROR.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3.1">QUIC Spec/Section 19.3.1</a>
 */
public interface AckRange {

    /**
     * A variable-length integer indicating the number of contiguous
     * unacknowledged packets preceding the packet number one lower than
     * the smallest in the preceding ACK Range.
     *
     * @return number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in
     * the preceding ACK Range
     */
    VariableLengthInteger getGap();

    /**
     * A variable-length integer indicating the number of
     * contiguous acknowledged packets preceding the largest packet
     * number, as determined by the preceding Gap.
     *
     * @return number of contiguous acknowledged packets preceding the largest packet number, as determined by the
     * preceding Gap
     */
    VariableLengthInteger getLength();
}

package com.timtrense.quic;


/**
 * The ACK frame uses the least significant bit (that is, type 0x03) to
 * indicate ECN feedback and report receipt of QUIC packets with
 * associated ECN codepoints of ECT(0), ECT(1), or CE in the packet's IP
 * header.  ECN Counts are only present when the ACK frame type is 0x03.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.3.2">QUIC Spec/Section 19.3.2</a>
 */
public interface EcnCount {

    /**
     * A variable-length integer representing the total number
     * of packets received with the ECT(0) codepoint in the packet number
     * space of the ACK frame
     *
     * @return total number of packets received with the ECT(0) codepoint in the packet number space of the ACK frame
     */
    VariableLengthInteger getEct0Count();

    /**
     * A variable-length integer representing the total number
     * of packets received with the ECT(1) codepoint in the packet number
     * space of the ACK frame
     *
     * @return total number of packets received with the ECT(1) codepoint in the packet number space of the ACK frame
     */
    VariableLengthInteger getEct1Count();

    /**
     * A variable-length integer representing the total number of
     * packets received with the CE codepoint in the packet number space
     * of the ACK frame.
     *
     * @return total number of packets received with the CE codepoint in the packet number space of the ACK frame
     */
    VariableLengthInteger getEcnCeCount();
}

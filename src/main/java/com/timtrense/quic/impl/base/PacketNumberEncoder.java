package com.timtrense.quic.impl.base;

/**
 * Encoder and Decoder for packet numbers with removed header protection as described
 * in Appendix A, QUIC Spec/Transport.
 *
 * @author Tim Trense
 */
public class PacketNumberEncoder {

    /**
     * Private constructor enforcing this class to not be instantiable
     */
    private PacketNumberEncoder() {}

    /**
     * decodes a serialized packet number
     *
     * @param truncatedPacketNumber            the serialized packet number
     * @param largestPacketNumber              the largest packet number received so far
     * @param bitLengthOfTruncatedPacketNumber the number of bits that were used to binary-encode that packet number
     * @return the decoded packet number
     */
    public static long decodePacketNumber(
            long truncatedPacketNumber,
            long largestPacketNumber,
            int bitLengthOfTruncatedPacketNumber
    ) {
        long expectedPacketNumber = largestPacketNumber + 1;
        long pnWindow = 1L << bitLengthOfTruncatedPacketNumber;
        long pnHalfWindow = pnWindow >> 1; // effectively dividing by 2
        long pnMask = -pnWindow; // effectively doing ~( pnWindow - 1 ) that is binary-inverted(window minus 1)

        long candidatePn = ( expectedPacketNumber & pnMask ) | truncatedPacketNumber;
        if ( candidatePn <= expectedPacketNumber - pnHalfWindow
                && candidatePn < ( 0x4000000000000000L /* 1L << 62 */ ) - pnWindow ) {
            candidatePn += pnWindow;
        }
        else if ( candidatePn > expectedPacketNumber + pnHalfWindow
                && candidatePn >= pnWindow ) {
            candidatePn -= pnWindow;
        }

        return candidatePn;
    }
}

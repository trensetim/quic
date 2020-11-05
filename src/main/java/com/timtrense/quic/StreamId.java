package com.timtrense.quic;

/**
 * A 62-bit unsigned integer, unique to all streams within a connection
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-2.1">QUIC Spec/Section 2.1</a>
 */
public interface StreamId {

    long MASK_INITIATOR = 0b0001;
    long MASK_DIRECTIONALITY = 0b0010;

    /**
     * @return the value of this streams id
     */
    VariableLengthInteger getValue();

    /**
     * @return the value of this streams id
     */
    default long getLongValue() {
        return getValue().longValue();
    }


    /**
     * unmasks the streams id from the least 2 significant bits which indicate initiator and uni/bi-directionality.
     *
     * @return the always incrementing part of the id
     */
    default long getCountingLongValue() {return getLongValue() >> 2;}

    /**
     * masks the streams id on the least 2 significant bits which indicate initiator and uni/bi-directionality.
     *
     * @return the part of the id which indicates initiator and directionality
     */
    default long getMask() {return getLongValue() & ( MASK_INITIATOR | MASK_DIRECTIONALITY );}

    /**
     * the uni/bi-directionality is indicated by the send-lest-significant bit meaning 1=uni, 0=bi -directional.
     *
     * @return whether this stream can only either send or receive data
     * @see #isBidirectional()
     */
    default boolean isUnidirectional() {
        return ( getLongValue() & MASK_DIRECTIONALITY ) == MASK_DIRECTIONALITY;
    }

    /**
     * returns the negated value of {@link #isUnidirectional()}
     *
     * @return whether this stream can both send and receive data
     * @see #isUnidirectional()
     */
    default boolean isBidirectional() {
        return ( getLongValue() & MASK_DIRECTIONALITY ) == 0;
    }

    /**
     * the initiator of this stream is indicated by the least-significant bit meaning 1=server, 0=client
     *
     * @return whether the stream was initiated by the server
     * @see #isClientInitiated()
     */
    default boolean isServerInitiated() {
        return ( getLongValue() & MASK_INITIATOR ) == MASK_INITIATOR;
    }

    /**
     * returns the negated value of {@link #isServerInitiated()}
     *
     * @return whether the stream was initiated by the client
     * @see #isServerInitiated()
     */
    default boolean isClientInitiated() {
        return ( getLongValue() & MASK_INITIATOR ) == 0;
    }
}

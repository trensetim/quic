package com.timtrense.quic;

/**
 * @param <T> the data type of the hold value
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2">QUIC Spec/Section 18.2</a>
 */
public interface TransportParameter<T> {

    /**
     * @return the id of the parameter
     */
    TransportParameterType getType();

    /**
     * @return the length in bytes required to encode the data
     */
    int getLength();

    /**
     * @return the actual hold value
     */
    T getValue();
}

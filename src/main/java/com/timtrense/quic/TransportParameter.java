package com.timtrense.quic;

/**
 * @param <Datatype> the data type of the hold value
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2">QUIC Spec/Section 18.2</a>
 */
public interface TransportParameter<Datatype> {

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
    Datatype getValue();
}

package com.timtrense.quic.impl.base;

import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;

import java.util.Collection;

/**
 * defines the complete transport configuration consisting of all applied parameters or their respective defaults
 *
 * @author Tim Trense
 */
public interface TransportParameterCollection {

    /**
     * queries the parameter or its respective default
     *
     * @param type the parameter type
     * @return the explicitly specified value for that parameter type or its respective default
     */
    TransportParameter<?> getParameter( TransportParameterType type );

    /**
     * returns the parameters default
     *
     * @param type the parameter type
     * @return the explicitly specified value for that parameter type or its respective default
     */
    TransportParameter<?> getParameterDefault( TransportParameterType type );

    /**
     * explicitly specifies the parameter, thus overriding the default
     *
     * @param parameter the value to specify, including the type
     * @return true on success, false if the given value cannot be applied to the parameter type (for instance
     * because the datatype mismatches or the value is out-of-bounds)
     */
    boolean setParameter( TransportParameter<?> parameter );

    /**
     * resets the parameters value to its default
     *
     * @param type the parameter type
     */
    void resetParameterValue( TransportParameterType type );

    /**
     * @return an unmodifiable view of all explicitly applied parameters
     */
    Collection<TransportParameter<?>> getAllExplicitParameters();

    /**
     * @param type the type to know whether it was explicitly set
     * @return true if the respective default was overridden by setting the parameter explicitly, false if
     * the default is used
     */
    boolean isExplicitlySet( TransportParameterType type );
}

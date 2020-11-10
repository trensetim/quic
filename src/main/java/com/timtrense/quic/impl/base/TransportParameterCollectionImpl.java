package com.timtrense.quic.impl.base;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.timtrense.quic.TransportParameter;
import com.timtrense.quic.TransportParameterType;

public class TransportParameterCollectionImpl implements TransportParameterCollection {

    public static final Map<TransportParameterType, TransportParameter<?>> PARAMETER_DEFAULT_VALUES;

    static {
        PARAMETER_DEFAULT_VALUES = new HashMap<>();
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.ORIGINAL_DESTINATION_CONNECTION_ID,
                new IntegerTransportParameterImpl( TransportParameterType.ORIGINAL_DESTINATION_CONNECTION_ID, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.MAX_IDLE_TIMEOUT,
                // 0 = no timeout
                new IntegerTransportParameterImpl( TransportParameterType.MAX_IDLE_TIMEOUT, 0 )
        );
        //TransportParameterType.STATELESS_RESET_TOKEN, null

        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.MAX_UDP_PAYLOAD_SIZE,
                new IntegerTransportParameterImpl( TransportParameterType.MAX_UDP_PAYLOAD_SIZE, 65527 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_DATA,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_DATA, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_STREAM_DATA_UNI,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_STREAM_DATA_UNI, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_STREAMS_BIDI,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_STREAMS_BIDI, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_MAX_STREAMS_UNI,
                // 0 = no limit
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_MAX_STREAMS_UNI, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.ACK_DELAY_EXPONENT,
                new IntegerTransportParameterImpl( TransportParameterType.ACK_DELAY_EXPONENT, 3 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.MAX_ACK_DELAY,
                new IntegerTransportParameterImpl( TransportParameterType.MAX_ACK_DELAY, 25 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.DISABLE_ACTIVE_MIGRATION,
                new FlagTransportParameterImpl( TransportParameterType.DISABLE_ACTIVE_MIGRATION, false )
        );

        //TransportParameterType.PREFERRED_ADDRESS, null

        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.ACTIVE_CONNECTION_ID_LIMIT,
                new IntegerTransportParameterImpl( TransportParameterType.ACTIVE_CONNECTION_ID_LIMIT, 2 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.INITIAL_SOURCE_CONNECTION_ID,
                new IntegerTransportParameterImpl( TransportParameterType.INITIAL_SOURCE_CONNECTION_ID, 0 )
        );
        PARAMETER_DEFAULT_VALUES.put(
                TransportParameterType.RETRY_SOURCE_CONNECTION_ID,
                new IntegerTransportParameterImpl( TransportParameterType.RETRY_SOURCE_CONNECTION_ID, 0 )
        );
    }

    private final Map<TransportParameterType, TransportParameter<?>> parameterMap = new HashMap<>();

    @Override
    public TransportParameter<?> getParameter( TransportParameterType type ) {
        TransportParameter<?> parameter = parameterMap.get( type );
        if ( parameter != null ) {
            return parameter;
        }
        parameter = PARAMETER_DEFAULT_VALUES.get( type );
        return parameter;
    }

    @Override
    public TransportParameter<?> getParameterDefault( TransportParameterType type ) {
        return PARAMETER_DEFAULT_VALUES.get( type );
    }

    @Override
    public boolean setParameter( TransportParameter<?> value ) {
        parameterMap.put( value.getType(), value );
        return true;
    }

    @Override
    public void resetParameterValue( TransportParameterType type ) {
        parameterMap.remove( type );
    }

    @Override
    public Collection<TransportParameter<?>> getAllExplicitParameters() {
        return parameterMap.values();
    }

    @Override
    public boolean isExplicitlySet( TransportParameterType type ) {
        return parameterMap.containsKey( type );
    }
}

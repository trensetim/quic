package com.timtrense.quic.impl.base;

import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import lombok.Data;

import com.timtrense.quic.EndpointRole;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.VariableLengthInteger;

@Data
public class StreamIdContextImpl implements StreamIdContext {

    private final EndpointRole role;
    private long nextCountingValue = 0L;
    private List<StreamId> knownStreamIds = new LinkedList<>();

    @Override
    public StreamId createNewId( boolean forUnidirectional ) {
        long value = nextCountingValue++; // post-increment
        StreamId created = new StreamIdImpl(
                new VariableLengthInteger(
                        ( value << 2 )
                                | ( role == EndpointRole.SERVER ? StreamId.MASK_INITIATOR : 0 )
                                | ( forUnidirectional ? StreamId.MASK_DIRECTIONALITY : 0 )
                )
        );
        knownStreamIds.add( created );
        return created;
    }

    @Override
    public StreamId notifyAboutNewId( long streamIdValue ) {
        if ( streamIdValue < 0 ) {
            return null;
        }

        StreamId testId = new StreamIdImpl( new VariableLengthInteger( streamIdValue ) );
        if ( testId.isServerInitiated() == ( role == EndpointRole.SERVER ) ) {
            // remotely created ids must indicate the inverted value for server initiated
            return null;
        }
        createIdsInBetween( nextCountingValue, testId.getCountingLongValue(), testId.getMask() );
        knownStreamIds.add( testId );
        knownStreamIds.sort( Comparator.comparing( StreamId::getLongValue ) );
        if ( nextCountingValue <= streamIdValue ) {
            nextCountingValue = ( streamIdValue >> 2 ) + 1;
        }
        return testId;
    }

    @Override
    public List<StreamId> getAllStreamIds() {
        return Collections.unmodifiableList( knownStreamIds );
    }

    private void createIdsInBetween( long currentCountingValue, long endCountingValue, long mask ) {
        for ( ; currentCountingValue < endCountingValue; currentCountingValue++ ) {
            StreamId inBetween = new StreamIdImpl( new VariableLengthInteger( ( currentCountingValue << 2 ) | mask ) );
            knownStreamIds.add( inBetween );
        }
    }
}

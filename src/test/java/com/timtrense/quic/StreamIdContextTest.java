package com.timtrense.quic;

import org.junit.Test;

import com.timtrense.quic.impl.base.StreamIdContext;
import com.timtrense.quic.impl.base.StreamIdContextImpl;

import static com.timtrense.quic.EndpointRole.CLIENT;
import static com.timtrense.quic.EndpointRole.SERVER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class StreamIdContextTest {

    @Test
    public void createNewId_requested3UnidirectionalIds_returns3ConsecutiveUnidirectionalIds() {
        StreamIdContext context = new StreamIdContextImpl( SERVER );
        StreamId uni1 = context.createNewUnidirectionalId();
        StreamId uni2 = context.createNewUnidirectionalId();
        StreamId uni3 = context.createNewUnidirectionalId();
        assertTrue( uni1.isUnidirectional() );
        assertTrue( uni2.isUnidirectional() );
        assertTrue( uni3.isUnidirectional() );
    }

    @Test
    public void createNewId_requested3IdsFromServerSide_returns3ServerInitiatedIds() {
        StreamIdContext context = new StreamIdContextImpl( SERVER );
        StreamId uni1 = context.createNewUnidirectionalId();
        StreamId uni2 = context.createNewUnidirectionalId();
        StreamId uni3 = context.createNewUnidirectionalId();
        assertTrue( uni1.isServerInitiated() );
        assertTrue( uni2.isServerInitiated() );
        assertTrue( uni3.isServerInitiated() );
    }

    @Test
    public void createNewId_requested3IdsFromClientSide_returns3ClientInitiatedIds() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );
        StreamId uni1 = context.createNewUnidirectionalId();
        StreamId uni2 = context.createNewUnidirectionalId();
        StreamId uni3 = context.createNewUnidirectionalId();
        assertTrue( uni1.isClientInitiated() );
        assertTrue( uni2.isClientInitiated() );
        assertTrue( uni3.isClientInitiated() );
    }

    @Test
    public void createNewId_requestedEach3IdsFromEachDirectionType_returnsCorrectDirectionTypes() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );
        StreamId uni1 = context.createNewUnidirectionalId();
        StreamId uni2 = context.createNewUnidirectionalId();
        StreamId uni3 = context.createNewUnidirectionalId();
        assertTrue( uni1.isUnidirectional() );
        assertTrue( uni2.isUnidirectional() );
        assertTrue( uni3.isUnidirectional() );

        StreamId bi1 = context.createNewBidirectionalId();
        StreamId bi2 = context.createNewBidirectionalId();
        StreamId bi3 = context.createNewBidirectionalId();
        assertTrue( bi1.isBidirectional() );
        assertTrue( bi2.isBidirectional() );
        assertTrue( bi3.isBidirectional() );
    }

    @Test
    public void createNewId_requestedEach3IdsFromAlternatingDirectionType_returnsCorrectDirectionTypes() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );
        StreamId uni1 = context.createNewUnidirectionalId();
        StreamId bi1 = context.createNewBidirectionalId();
        StreamId uni2 = context.createNewUnidirectionalId();
        StreamId bi2 = context.createNewBidirectionalId();
        StreamId uni3 = context.createNewUnidirectionalId();
        StreamId bi3 = context.createNewBidirectionalId();
        assertTrue( uni1.isUnidirectional() );
        assertTrue( bi1.isBidirectional() );
        assertTrue( uni2.isUnidirectional() );
        assertTrue( bi2.isBidirectional() );
        assertTrue( uni3.isUnidirectional() );
        assertTrue( bi3.isBidirectional() );
    }

    @Test
    public void createNewId_notifiedAboutNewUniServerId_returnsThisVeryId() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );

        // notify about 0b001000 with uni-mask and server-mask
        StreamId id = context.notifyAboutNewId( 0b001011 );

        assertTrue( id.isUnidirectional() );
        assertTrue( id.isServerInitiated() );
        assertEquals( 0b001011, id.getLongValue() );
    }

    @Test
    public void createNewId_requestedIdAfterNotificationOnNewUnidirectional_returnsUnusedUnidirectional() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );

        // notify about 0b001000 with uni-mask and server-mask
        StreamId notifiedId = context.notifyAboutNewId( 0b001011 );
        StreamId nextUnidirectional = context.createNewUnidirectionalId();

        assertEquals( 0b001110, nextUnidirectional.getLongValue() );
    }

    @Test
    public void createNewId_requestedIdAfter2NotificationOnNewUnidirectional_returnsUnusedUnidirectional() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );

        // notify about 0b001000 with uni-mask and server-mask
        StreamId notifiedId = context.notifyAboutNewId( 0b001011 );
        StreamId notifiedId2 = context.notifyAboutNewId( 0b001111 );
        StreamId nextUnidirectional = context.createNewUnidirectionalId();

        assertEquals( 0b010010, nextUnidirectional.getLongValue() );
    }

    @Test
    public void createNewId_notificationOnId_createsIdsInBetween() {
        StreamIdContext context = new StreamIdContextImpl( CLIENT );

        // notify about 0b001000 with uni-mask and server-mask
        StreamId notifiedId = context.notifyAboutNewId( 0b001011 );

        assertEquals( 3, context.getAllStreamIds().size() );
        assertEquals( 0b000011, context.getAllStreamIds().get( 0 ).getLongValue() );
        assertEquals( 0b000111, context.getAllStreamIds().get( 1 ).getLongValue() );
        assertEquals( 0b001011, context.getAllStreamIds().get( 2 ).getLongValue() );
    }
}

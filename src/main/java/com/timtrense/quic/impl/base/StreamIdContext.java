package com.timtrense.quic.impl.base;

import com.timtrense.quic.StreamId;

import java.util.List;

/**
 * The context within which {@link StreamId StreamIds} are generated and used.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-2.1">QUIC Spec/Section 2.1</a>
 */
public interface StreamIdContext {

    /**
     * @return whether this context belongs to the servers side, thus creating only {@link StreamId StreamIds}
     * which are server-initiated
     */
    boolean isServerSide();

    /**
     * creates a new {@link StreamId} that is not yet used. By specification this gives strictly monotonic
     * incrementing values.
     *
     * this method is not thread-safe unless synchronized on this instance.
     *
     * @param forUnidirectional whether the id should indicate a unidirectional stream (true) or a
     *                          bidirectional one (false)
     * @return a new, unique, not yet used {@link StreamId}
     */
    StreamId createNewId( boolean forUnidirectional );

    /**
     * notifies the context that a new stream id was introduced to the connection (presumably by the remote).
     * all remotely created stream ids must indicated the inverted value for server-initiation with respect to
     * this context.
     * when invoked, the method creates all ids of the given type (initiator and directionality) in between
     * the current counting step and the given id.
     *
     * this method is not thread-safe unless synchronized on this instance.
     *
     * @param streamIdValue the remotely introduced new id
     * @return a new {@link StreamId} instance for that value or null if that value is either invalid or already used
     */
    StreamId notifyAboutNewId( long streamIdValue );

    /**
     * @return an immutable view to all ids sorted by their values which naturally contains each known id only once
     */
    List<StreamId> getAllStreamIds();

    /**
     * Wrapper for {@code createNewId(true)}
     *
     * @return a new, unique, not yet used {@link StreamId}, which will always
     * give {@code true} for {@link StreamId#isUnidirectional()} and {@code false} for {@link StreamId#isBidirectional()}
     */
    default StreamId createNewUnidirectionalId() {
        return createNewId( true );
    }

    /**
     * Wrapper for {@code createNewId(false)}
     *
     * @return a new, unique, not yet used {@link StreamId}, which will always
     * give {@code true} for {@link StreamId#isBidirectional()} and {@code false} for {@link StreamId#isUnidirectional()}
     */
    default StreamId createNewBidirectionalId() {
        return createNewId( false );
    }
}

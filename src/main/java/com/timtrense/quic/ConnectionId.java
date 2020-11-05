package com.timtrense.quic;

/**
 * Each connection possesses a set of connection identifiers, or
 * connection IDs, each of which can identify the connection.
 * Connection IDs are independently selected by endpoints; each endpoint
 * selects the connection IDs that its peer uses.
 *
 * The primary function of a connection ID is to ensure that changes in
 * addressing at lower protocol layers (UDP, IP) do not cause packets
 * for a QUIC connection to be delivered to the wrong endpoint.  Each
 * endpoint selects connection IDs using an implementation-specific (and
 * perhaps deployment-specific) method that will allow packets with that
 * connection ID to be routed back to the endpoint and to be identified
 * by the endpoint upon receipt.
 *
 * Connection IDs MUST NOT contain any information that can be used by
 * an external observer (that is, one that does not cooperate with the
 * issuer) to correlate them with other connection IDs for the same
 * connection.  As a trivial example, this means the same connection ID
 * MUST NOT be issued more than once on the same connection.
 *
 * Packets with long headers include Source Connection ID and
 * Destination Connection ID fields.  These fields are used to set the
 * connection IDs for new connections; see Section 7.2 for details.
 *
 * Packets with short headers (Section 17.3) only include the
 * Destination Connection ID and omit the explicit length.  The length
 * of the Destination Connection ID field is expected to be known to
 * endpoints.  Endpoints using a load balancer that routes based on
 * connection ID could agree with the load balancer on a fixed length
 * for connection IDs, or agree on an encoding scheme.  A fixed portion
 * could encode an explicit length, which allows the entire connection
 * ID to vary in length and still be used by the load balancer.
 *
 * A Version Negotiation (Section 17.2.1) packet echoes the connection
 * IDs selected by the client, both to ensure correct routing toward the
 * client and to demonstrate that the packet is in response to a packet
 * sent by the client.
 *
 * A zero-length connection ID can be used when a connection ID is not
 * needed to route to the correct endpoint.  However, multiplexing
 * connections on the same local IP address and port while using zero-
 * length connection IDs will cause failures in the presence of peer
 * connection migration, NAT rebinding, and client port reuse.  An
 * endpoint MUST NOT use the same IP address and port for multiple
 * connections with zero-length connection IDs, unless it is certain
 * that those protocol features are not in use.
 *
 * When an endpoint uses a non-zero-length connection ID, it needs to
 * ensure that the peer has a supply of connection IDs from which to
 * choose for packets sent to the endpoint.  These connection IDs are
 * supplied by the endpoint using the NEW_CONNECTION_ID frame
 * (Section 19.15).
 *
 * <p/>
 *
 * <h2>Issuing Connection IDs</h2>
 * Each Connection ID has an associated sequence number to assist in
 * detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer
 * to the same value.  The initial connection ID issued by an endpoint
 * is sent in the Source Connection ID field of the long packet header
 * (Section 17.2) during the handshake.  The sequence number of the
 * initial connection ID is 0.  If the preferred_address transport
 * parameter is sent, the sequence number of the supplied connection ID
 * is 1.
 *
 * Additional connection IDs are communicated to the peer using
 * NEW_CONNECTION_ID frames (Section 19.15).  The sequence number on
 * each newly issued connection ID MUST increase by 1.  The connection
 * ID randomly selected by the client in the Initial packet and any
 * connection ID provided by a Retry packet are not assigned sequence
 * numbers unless a server opts to retain them as its initial connection
 * ID.
 *
 * When an endpoint issues a connection ID, it MUST accept packets that
 * carry this connection ID for the duration of the connection or until
 * its peer invalidates the connection ID via a RETIRE_CONNECTION_ID
 * frame (Section 19.16).  Connection IDs that are issued and not
 * retired are considered active; any active connection ID is valid for
 * use with the current connection at any time, in any packet type.
 * This includes the connection ID issued by the server via the
 * preferred_address transport parameter.
 *
 * An endpoint SHOULD ensure that its peer has a sufficient number of
 * available and unused connection IDs.  Endpoints advertise the number
 * of active connection IDs they are willing to maintain using the
 * active_connection_id_limit transport parameter.  An endpoint MUST NOT
 * provide more connection IDs than the peer's limit.  An endpoint MAY
 * send connection IDs that temporarily exceed a peer's limit if the
 * NEW_CONNECTION_ID frame also requires the retirement of any excess,
 * by including a sufficiently large value in the Retire Prior To field.
 *
 * A NEW_CONNECTION_ID frame might cause an endpoint to add some active
 * connection IDs and retire others based on the value of the Retire
 * Prior To field.  After processing a NEW_CONNECTION_ID frame and
 * adding and retiring active connection IDs, if the number of active
 * connection IDs exceeds the value advertised in its
 * active_connection_id_limit transport parameter, an endpoint MUST
 * close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
 *
 * An endpoint SHOULD supply a new connection ID when the peer retires a
 * connection ID.  If an endpoint provided fewer connection IDs than the
 * peer's active_connection_id_limit, it MAY supply a new connection ID
 * when it receives a packet with a previously unused connection ID.  An
 * endpoint MAY limit the total number of connection IDs issued for each
 * connection to avoid the risk of running out of connection IDs; see
 * Section 10.3.2.  An endpoint MAY also limit the issuance of
 * connection IDs to reduce the amount of per-path state it maintains,
 * such as path validation status, as its peer might interact with it
 * over as many paths as there are issued connection IDs.
 *
 * An endpoint that initiates migration and requires non-zero-length
 * connection IDs SHOULD ensure that the pool of connection IDs
 * available to its peer allows the peer to use a new connection ID on
 * migration, as the peer will be unable to respond if the pool is
 * exhausted.
 *
 * <p/>
 * <h1>Consuming and Retiring Connection IDs</h1>
 * An endpoint can change the connection ID it uses for a peer to
 * another available one at any time during the connection.  An endpoint
 * consumes connection IDs in response to a migrating peer; see
 * Section 9.5 for more.
 *
 * An endpoint maintains a set of connection IDs received from its peer,
 * any of which it can use when sending packets.  When the endpoint
 * wishes to remove a connection ID from use, it sends a
 * RETIRE_CONNECTION_ID frame to its peer.  Sending a
 * RETIRE_CONNECTION_ID frame indicates that the connection ID will not
 * be used again and requests that the peer replace it with a new
 * connection ID using a NEW_CONNECTION_ID frame.
 *
 * As discussed in Section 9.5, endpoints limit the use of a connection
 * ID to packets sent from a single local address to a single
 * destination address.  Endpoints SHOULD retire connection IDs when
 * they are no longer actively using either the local or destination
 * address for which the connection ID was used.
 *
 * An endpoint might need to stop accepting previously issued connection
 * IDs in certain circumstances.  Such an endpoint can cause its peer to
 * retire connection IDs by sending a NEW_CONNECTION_ID frame with an
 * increased Retire Prior To field.  The endpoint SHOULD continue to
 * accept the previously issued connection IDs until they are retired by
 * the peer.  If the endpoint can no longer process the indicated
 * connection IDs, it MAY close the connection.
 *
 * Upon receipt of an increased Retire Prior To field, the peer MUST
 * stop using the corresponding connection IDs and retire them with
 * RETIRE_CONNECTION_ID frames before adding the newly provided
 * connection ID to the set of active connection IDs.  This ordering
 * allows an endpoint to replace all active connection IDs without the
 * possibility of a peer having no available connection IDs and without
 * exceeding the limit the peer sets in the active_connection_id_limit
 * transport parameter; see Section 18.2.  Failure to cease using the
 * connection IDs when requested can result in connection failures, as
 * the issuing endpoint might be unable to continue using the connection
 * IDs with the active connection.
 *
 * An endpoint SHOULD limit the number of connection IDs it has retired
 * locally and have not yet been acknowledged.  An endpoint SHOULD allow
 * for sending and tracking a number of RETIRE_CONNECTION_ID frames of
 * at least twice the active_connection_id limit.  An endpoint MUST NOT
 * forget a connection ID without retiring it, though it MAY choose to
 * treat having connection IDs in need of retirement that exceed this
 * limit as a connection error of type CONNECTION_ID_LIMIT_ERROR.
 *
 * Endpoints SHOULD NOT issue updates of the Retire Prior To field
 * before receiving RETIRE_CONNECTION_ID frames that retire all
 * connection IDs indicated by the previous Retire Prior To value.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-5.1">QUIC Spec/Section 5.1</a>
 */
public interface ConnectionId {

    /**
     * connection ids are unsigned
     *
     * @return the value of this streams id, non-negative
     */
    byte[] getValue();

    /**
     * Each Connection ID has an associated sequence number to assist in
     * detecting when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer
     * to the same value.  The initial connection ID issued by an endpoint
     * is sent in the Source Connection ID field of the long packet header
     * (Section 17.2) during the handshake.  The sequence number of the
     * initial connection ID is 0.  If the preferred_address transport
     * parameter is sent, the sequence number of the supplied connection ID
     * is 1.
     *
     * @return the associated sequence number
     */
    VariableLengthInteger getSequenceNumber();
}

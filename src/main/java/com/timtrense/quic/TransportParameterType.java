package com.timtrense.quic;

import lombok.Getter;

/**
 * This class contains all defined connection parameters for QUIC.
 *
 * If present, transport parameters that set initial flow control limits
 * (initial_max_stream_data_bidi_local,
 * initial_max_stream_data_bidi_remote, and initial_max_stream_data_uni)
 * are equivalent to sending a MAX_STREAM_DATA frame (Section 19.10) on
 * every stream of the corresponding type immediately after opening.  If
 * the transport parameter is absent, streams of that type start with a
 * flow control limit of 0.
 *
 * A client MUST NOT include any server-only transport parameter:
 * original_destination_connection_id, preferred_address,
 * retry_source_connection_id, or stateless_reset_token.  A server MUST
 * treat receipt of any of these transport parameters as a connection
 * error of type TRANSPORT_PARAMETER_ERROR.
 *
 * <h2>Reserved Transport Parameters</h2>
 * Transport parameters with an identifier of the form "31 * N + 27" for
 * integer values of N are reserved to exercise the requirement that
 * unknown transport parameters be ignored.  These transport parameters
 * have no semantics, and may carry arbitrary values.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.1">QUIC Spec/Section 18.1</a>
 */
public enum TransportParameterType {

    /**
     * The value of the
     * Destination Connection ID field from the first Initial packet sent
     * by the client; see Section 7.3.  This transport parameter is only
     * sent by a server.
     */
    ORIGINAL_DESTINATION_CONNECTION_ID( 0x00, true, byte[].class /* variable length, usually 8 bytes */ ),
    /**
     * The max idle timeout is a value in
     * milliseconds that is encoded as an integer; see (Section 10.1).
     * Idle timeout is disabled when both endpoints omit this transport
     * parameter or specify a value of 0.
     */
    MAX_IDLE_TIMEOUT( 0x01, false, long.class ),
    /**
     * A stateless reset token is used in
     * verifying a stateless reset; see Section 10.3.  This parameter is
     * a sequence of 16 bytes.  This transport parameter MUST NOT be sent
     * by a client, but MAY be sent by a server.  A server that does not
     * send this transport parameter cannot use stateless reset
     * (Section 10.3) for the connection ID negotiated during the
     * handshake.
     */
    STATELESS_RESET_TOKEN( 0x02, true, byte[].class /* length 16*/ ),
    /**
     * max_udp_payload_size (0x03):  The maximum UDP payload size parameter
     * is an integer value that limits the size of UDP payloads that the
     * endpoint is willing to receive.  UDP datagrams with payloads
     * larger than this limit are not likely to be processed by the
     * receiver.
     *
     * The default for this parameter is the maximum permitted UDP
     * payload of 65527.  Values below 1200 are invalid.
     *
     * This limit does act as an additional constraint on datagram size
     * in the same way as the path MTU, but it is a property of the
     * endpoint and not the path; see Section 14.  It is expected that
     * this is the space an endpoint dedicates to holding incoming
     * packets.
     */
    MAX_UDP_PAYLOAD_SIZE( 0x03, false, long.class ),
    /**
     * The initial maximum data parameter is an
     * integer value that contains the initial value for the maximum
     * amount of data that can be sent on the connection.  This is
     * equivalent to sending a MAX_DATA (Section 19.9) for the connection
     * immediately after completing the handshake.
     */
    INITIAL_MAX_DATA( 0x04, false, long.class ),
    /**
     * This parameter is an
     * integer value specifying the initial flow control limit for
     * locally-initiated bidirectional streams.  This limit applies to
     * newly created bidirectional streams opened by the endpoint that
     * sends the transport parameter.  In client transport parameters,
     * this applies to streams with an identifier with the least
     * significant two bits set to 0x0; in server transport parameters,
     * this applies to streams with the least significant two bits set to
     * 0x1.
     */
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL( 0x05, false, long.class ),
    /**
     * This parameter is an
     * integer value specifying the initial flow control limit for peer-
     * initiated bidirectional streams.  This limit applies to newly
     * created bidirectional streams opened by the endpoint that receives
     * the transport parameter.  In client transport parameters, this
     * applies to streams with an identifier with the least significant
     * two bits set to 0x1; in server transport parameters, this applies
     * to streams with the least significant two bits set to 0x0.
     */
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE( 0x06, false, long.class ),
    /**
     * This parameter is an integer
     * value specifying the initial flow control limit for unidirectional
     * streams.  This limit applies to newly created unidirectional
     * streams opened by the endpoint that receives the transport
     * parameter.  In client transport parameters, this applies to
     * streams with an identifier with the least significant two bits set
     * to 0x3; in server transport parameters, this applies to streams
     * with the least significant two bits set to 0x2.
     */
    INITIAL_MAX_STREAM_DATA_UNI( 0x07, false, long.class ),
    /**
     * The initial maximum bidirectional
     * streams parameter is an integer value that contains the initial
     * maximum number of bidirectional streams the peer may initiate.  If
     * this parameter is absent or zero, the peer cannot open
     * bidirectional streams until a MAX_STREAMS frame is sent.  Setting
     * this parameter is equivalent to sending a MAX_STREAMS
     * (Section 19.11) of the corresponding type with the same value.
     */
    INITIAL_MAX_STREAMS_BIDI( 0x08, false, long.class ),
    /**
     * The initial maximum unidirectional
     * streams parameter is an integer value that contains the initial
     * maximum number of unidirectional streams the peer may initiate.
     * If this parameter is absent or zero, the peer cannot open
     * unidirectional streams until a MAX_STREAMS frame is sent.  Setting
     * this parameter is equivalent to sending a MAX_STREAMS
     * (Section 19.11) of the corresponding type with the same value.
     */
    INITIAL_MAX_STREAMS_UNI( 0x09, false, long.class ),
    /**
     * The acknowledgement delay exponent is an
     * integer value indicating an exponent used to decode the ACK Delay
     * field in the ACK frame (Section 19.3).  If this value is absent, a
     * default value of 3 is assumed (indicating a multiplier of 8).
     * Values above 20 are invalid.
     */
    ACK_DELAY_EXPONENT( 0x0a, false, long.class ),
    /**
     * The maximum acknowledgement delay is an
     * integer value indicating the maximum amount of time in
     * milliseconds by which the endpoint will delay sending
     * acknowledgments.  This value SHOULD include the receiver's
     * expected delays in alarms firing.  For example, if a receiver sets
     * a timer for 5ms and alarms commonly fire up to 1ms late, then it
     * should send a max_ack_delay of 6ms.  If this value is absent, a
     * default of 25 milliseconds is assumed.  Values of 2^14 or greater
     * are invalid.
     */
    MAX_ACK_DELAY( 0x0b, false, long.class ),
    /**
     * The disable active migration
     * transport parameter is included if the endpoint does not support
     * active connection migration (Section 9) on the address being used
     * during the handshake.  When a peer sets this transport parameter,
     * an endpoint MUST NOT use a new local address when sending to the
     * address that the peer used during the handshake.  This transport
     * parameter does not prohibit connection migration after a client
     * has acted on a preferred_address transport parameter.  This
     * parameter is a zero-length value.
     */
    DISABLE_ACTIVE_MIGRATION( 0x0c, false, boolean.class ),
    /**
     * The server's preferred address is used to
     * effect a change in server address at the end of the handshake, as
     * described in Section 9.6.  This transport parameter is only sent
     * by a server.  Servers MAY choose to only send a preferred address
     * of one address family by sending an all-zero address and port
     * (0.0.0.0:0 or ::.0) for the other family.  IP addresses are
     * encoded in network byte order.
     *
     * The preferred_address transport parameter contains an address and
     * port for both IP version 4 and 6.  The four-byte IPv4 Address
     * field is followed by the associated two-byte IPv4 Port field.
     * This is followed by a 16-byte IPv6 Address field and two-byte IPv6
     * Port field.  After address and port pairs, a Connection ID Length
     * field describes the length of the following Connection ID field.
     * Finally, a 16-byte Stateless Reset Token field includes the
     * stateless reset token associated with the connection ID.  The
     * format of this transport parameter is shown in Figure 22.
     *
     * The Connection ID field and the Stateless Reset Token field
     * contain an alternative connection ID that has a sequence number of
     * 1; see Section 5.1.1.  Having these values sent alongside the
     * preferred address ensures that there will be at least one unused
     * active connection ID when the client initiates migration to the
     * preferred address.
     *
     * The Connection ID and Stateless Reset Token fields of a preferred
     * address are identical in syntax and semantics to the corresponding
     * fields of a NEW_CONNECTION_ID frame (Section 19.15).  A server
     * that chooses a zero-length connection ID MUST NOT provide a
     * preferred address.  Similarly, a server MUST NOT include a zero-
     * length connection ID in this transport parameter.  A client MUST
     * treat violation of these requirements as a connection error of
     * type TRANSPORT_PARAMETER_ERROR.
     *
     * <pre>
     * Preferred Address {
     *      IPv4 Address (32),
     *      IPv4 Port (16),
     *      IPv6 Address (128),
     *      IPv6 Port (16),
     *      Connection ID Length (8),
     *      Connection ID (..),
     *      Stateless Reset Token (128),
     * }
     * </pre>
     * Figure 22: Preferred Address format
     */
    PREFERRED_ADDRESS( 0x0d, true, PreferredAddress.class ),
    /**
     * The active connection ID limit is
     * an integer value specifying the maximum number of connection IDs
     * from the peer that an endpoint is willing to store.  This value
     * includes the connection ID received during the handshake, that
     * received in the preferred_address transport parameter, and those
     * received in NEW_CONNECTION_ID frames.  The value of the
     * active_connection_id_limit parameter MUST be at least 2.  An
     * endpoint that receives a value less than 2 MUST close the
     * connection with an error of type TRANSPORT_PARAMETER_ERROR.  If
     * this transport parameter is absent, a default of 2 is assumed.  If
     * an endpoint issues a zero-length connection ID, it will never send
     * a NEW_CONNECTION_ID frame and therefore ignores the
     * active_connection_id_limit value received from its peer.
     */
    ACTIVE_CONNECTION_ID_LIMIT( 0x0e, false, long.class ),
    /**
     * The value that the endpoint
     * included in the Source Connection ID field of the first Initial
     * packet it sends for the connection; see Section 7.3.
     */
    INITIAL_SOURCE_CONNECTION_ID( 0x0f, false, byte[].class /* variable length, usually 8 bytes */ ),
    /**
     * The value that the server
     * included in the Source Connection ID field of a Retry packet; see
     * Section 7.3.  This transport parameter is only sent by a server.
     */
    RETRY_SOURCE_CONNECTION_ID( 0x10, true, byte[].class /* variable length, usually 8 bytes */ );

    @Getter
    private final int value;
    @Getter
    private final boolean serverOnly;
    @Getter
    private final Class<?> datatype;

    TransportParameterType( int value, boolean serverOnly, Class<?> datatype ) {
        this.value = value;
        this.serverOnly = serverOnly;
        this.datatype = datatype;
    }

    public static TransportParameterType findByValue( int value ) {
        for ( TransportParameterType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

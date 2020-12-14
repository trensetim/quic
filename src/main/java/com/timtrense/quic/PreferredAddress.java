package com.timtrense.quic;

/**
 * The server's preferred address is used to
 * effect a change in server address at the end of the handshake, as
 * described in Section 9.6.  This transport parameter is only sent
 * by a server.  Servers MAY choose to only send a preferred address
 * of one address family by sending an all-zero address and port
 * (0.0.0.0:0 or ::.0) for the other family.  IP addresses are
 * encoded in network byte order.
 * <p/>
 * The preferred_address transport parameter contains an address and
 * port for both IP version 4 and 6.  The four-byte IPv4 Address
 * field is followed by the associated two-byte IPv4 Port field.
 * This is followed by a 16-byte IPv6 Address field and two-byte IPv6
 * Port field.  After address and port pairs, a Connection ID Length
 * field describes the length of the following Connection ID field.
 * Finally, a 16-byte Stateless Reset Token field includes the
 * stateless reset token associated with the connection ID.  The
 * format of this transport parameter is shown in Figure 22.
 * <p/>
 * The Connection ID field and the Stateless Reset Token field
 * contain an alternative connection ID that has a sequence number of
 * 1; see Section 5.1.1.  Having these values sent alongside the
 * preferred address ensures that there will be at least one unused
 * active connection ID when the client initiates migration to the
 * preferred address.
 * <p/>
 * The Connection ID and Stateless Reset Token fields of a preferred
 * address are identical in syntax and semantics to the corresponding
 * fields of a NEW_CONNECTION_ID frame (Section 19.15).  A server
 * that chooses a zero-length connection ID MUST NOT provide a
 * preferred address.  Similarly, a server MUST NOT include a zero-
 * length connection ID in this transport parameter.  A client MUST
 * treat violation of these requirements as a connection error of
 * type TRANSPORT_PARAMETER_ERROR.
 * <pre>
 * Preferred Address {
 *   IPv4 Address (32),
 *   IPv4 Port (16),
 *   IPv6 Address (128),
 *   IPv6 Port (16),
 *   Connection ID Length (8),
 *   Connection ID (..),
 *   Stateless Reset Token (128)
 * }
 * Figure 22: Preferred Address format
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#page-125">QUIC Spec/Page 125</a>
 */
public interface PreferredAddress {

    byte[] getIpv4Address();

    int getIpv4Port();

    byte[] getIpv6Address();

    int getIpv6Port();

    ConnectionId getConnectionId();

    StatelessResetToken getStatelessResetToken();
}

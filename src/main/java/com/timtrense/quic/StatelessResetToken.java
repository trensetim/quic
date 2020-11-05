package com.timtrense.quic;

/**
 * A 128-bit value that will be used for a
 * stateless reset when the associated connection ID is used; see
 * Section 10.3.
 *
 * A stateless reset is provided as an option of last resort for an
 * endpoint that does not have access to the state of a connection.  A
 * crash or outage might result in peers continuing to send data to an
 * endpoint that is unable to properly continue the connection.  An
 * endpoint MAY send a stateless reset in response to receiving a packet
 * that it cannot associate with an active connection.
 *
 * A stateless reset is not appropriate for indicating errors in active
 * connections.  An endpoint that wishes to communicate a fatal
 * connection error MUST use a CONNECTION_CLOSE frame if it is able.
 *
 * To support this process, a token is sent by endpoints.  The token is
 * carried in the Stateless Reset Token field of a NEW_CONNECTION_ID
 * frame.  Servers can also specify a stateless_reset_token transport
 * parameter during the handshake that applies to the connection ID that
 * it selected during the handshake; clients cannot use this transport
 * parameter because their transport parameters do not have
 * confidentiality protection.  These tokens are protected by
 * encryption, so only client and server know their value.  Tokens are
 * invalidated when their associated connection ID is retired via a
 * RETIRE_CONNECTION_ID frame (Section 19.16).
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-10.3">QUIC Spec/Section 10.3</a>
 */
public interface StatelessResetToken {

    byte[] getValue();

}

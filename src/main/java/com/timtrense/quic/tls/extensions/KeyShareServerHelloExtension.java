package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.KeyShareEntry;

/**
 * In a ServerHello message, the "extension_data" field of this
 * extension contains a KeyShareServerHello value:
 *
 * <pre>
 * struct {
 *     KeyShareEntry server_share;
 * } KeyShareServerHello;
 * </pre>
 *
 * If using (EC)DHE key establishment, servers offer exactly one
 * KeyShareEntry in the ServerHello.  This value MUST be in the same
 * group as the KeyShareEntry value offered by the client that the
 * server has selected for the negotiated key exchange.  Servers
 * MUST NOT send a KeyShareEntry for any group not indicated in the
 * client's "supported_groups" extension and MUST NOT send a
 * KeyShareEntry when using the "psk_ke" PskKeyExchangeMode.  If using
 * (EC)DHE key establishment and a HelloRetryRequest containing a
 * "key_share" extension was received by the client, the client MUST
 * verify that the selected NamedGroup in the ServerHello is the same as
 * that in the HelloRetryRequest.  If this check fails, the client MUST
 * abort the handshake with an "illegal_parameter" alert.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8">TLS 1.3 Spec/Section 4.2.8</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class KeyShareServerHelloExtension extends KeyShareExtensionBase {

    /**
     * A single KeyShareEntry value that is in the same group
     * as one of the client's shares.
     */
    private KeyShareEntry serverShare;
}

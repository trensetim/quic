package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.NamedGroup;

/**
 * In a HelloRetryRequest message, the "extension_data" field of this
 * extension contains a KeyShareHelloRetryRequest value:
 *
 * <pre>
 * struct {
 *      NamedGroup selected_group;
 * } KeyShareHelloRetryRequest;
 * </pre>
 *
 * Upon receipt of this extension in a HelloRetryRequest, the client
 * MUST verify that (1) the selected_group field corresponds to a group
 * which was provided in the "supported_groups" extension in the
 * original ClientHello and (2) the selected_group field does not
 * correspond to a group which was provided in the "key_share" extension
 * in the original ClientHello.  If either of these checks fails, then
 * the client MUST abort the handshake with an "illegal_parameter"
 * alert.  Otherwise, when sending the new ClientHello, the client MUST
 * replace the original "key_share" extension with one containing only a
 * new KeyShareEntry for the group indicated in the selected_group field
 * of the triggering HelloRetryRequest.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8">TLS 1.3 Spec/Section 4.2.8</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class KeyShareHelloRetryRequestExtension extends KeyShareExtensionBase {

    /**
     * The mutually supported group the server intends to
     * negotiate and is requesting a retried ClientHello/KeyShare for.
     */
    private NamedGroup selectedGroup;
}

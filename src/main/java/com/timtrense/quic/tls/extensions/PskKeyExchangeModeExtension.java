package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.PskKeyExchangeMode;

/**
 * // PSK = Pre-Shared-Key. <br/>
 *
 * <pre>
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 * </pre>
 *
 * In order to use PSKs, clients MUST also send a
 * "psk_key_exchange_modes" extension.  The semantics of this extension
 * are that the client only supports the use of PSKs with these modes,
 * which restricts both the use of PSKs offered in this ClientHello and
 * those which the server might supply via NewSessionTicket.
 * <p/>
 * A client MUST provide a "psk_key_exchange_modes" extension if it
 * offers a "pre_shared_key" extension.  If clients offer
 * "pre_shared_key" without a "psk_key_exchange_modes" extension,
 * servers MUST abort the handshake.  Servers MUST NOT select a key
 * exchange mode that is not listed by the client.  This extension also
 * restricts the modes for use with PSK resumption.  Servers SHOULD NOT
 * send NewSessionTicket with tickets that are not compatible with the
 * advertised modes; however, if a server does so, the impact will just
 * be that the client's attempts at resumption fail.
 * <p/>
 * <b>The server MUST NOT send a "psk_key_exchange_modes" extension.</b>
 * <p/>
 * Any future values that are allocated must ensure that the transmitted
 * protocol messages unambiguously identify which mode was selected by
 * the server; at present, this is indicated by the presence of the
 * "key_share" in the ServerHello.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.9">TLS 1.3 Spec/Section 4.2.9</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class PskKeyExchangeModeExtension extends Extension {

    /**
     * <b>Implementation Note: this field will be set to an empty array upon instantiation</b>
     */
    private PskKeyExchangeMode[] keyExchangeModes = new PskKeyExchangeMode[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.PSK_KEY_EXCHANGE_MODES;
    }
}

package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * <pre>
 * struct {
 *     opaque cookie<1..2^16-1>;
 * } Cookie;
 * </pre>
 *
 * Cookies serve two primary purposes:
 * <ul>
 *    <li>
 *       Allowing the server to force the client to demonstrate
 *       reachability at their apparent network address (thus providing a
 *       measure of DoS protection).  This is primarily useful for
 *       non-connection-oriented transports (see [RFC6347] for an example
 *       of this).
 *    </li>
 *    <li>
 *       Allowing the server to offload state to the client, thus allowing
 *       it to send a HelloRetryRequest without storing any state.  The
 *       server can do this by storing the hash of the ClientHello in the
 *       HelloRetryRequest cookie (protected with some suitable integrity
 *       protection algorithm).
 *    </li>
 * </ul>
 *
 * When sending a HelloRetryRequest, the server MAY provide a "cookie"
 * extension to the client (this is an exception to the usual rule that
 * the only extensions that may be sent are those that appear in the
 * ClientHello).  When sending the new ClientHello, the client MUST copy
 * the contents of the extension received in the HelloRetryRequest into
 * a "cookie" extension in the new ClientHello.  Clients MUST NOT use
 * cookies in their initial ClientHello in subsequent connections.
 *
 * When a server is operating statelessly, it may receive an unprotected
 * record of type change_cipher_spec between the first and second
 * ClientHello (see Section 5).  Since the server is not storing any
 * state, this will appear as if it were the first message to be
 * received.  Servers operating statelessly MUST ignore these records.
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class CookieExtension extends Extension {

    /**
     * 1 up to (2 pow 16 -1) bytes of cookie data
     */
    private byte[] cookie;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.COOKIE;
    }
}

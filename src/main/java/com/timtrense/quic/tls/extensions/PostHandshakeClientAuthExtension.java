package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * <pre>
 *  struct {} PostHandshakeAuth;
 * </pre>
 *
 * The "post_handshake_auth" extension is used to indicate that a client
 * is willing to perform post-handshake authentication (Section 4.6.2).
 * Servers MUST NOT send a post-handshake CertificateRequest to clients
 * which do not offer this extension.  Servers MUST NOT send this
 * extension.
 * <p/>
 * The "extension_data" field of the "post_handshake_auth" extension is
 * zero length.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.6">TLS 1.3 Spec/Section 4.2.6</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class PostHandshakeClientAuthExtension extends Extension {

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.POST_HANDSHAKE_AUTH;
    }
}

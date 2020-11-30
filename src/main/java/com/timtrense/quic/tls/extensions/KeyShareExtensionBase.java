package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * The "key_share" extension contains the endpoint's cryptographic
 * parameters.
 * <p/>
 * Clients MAY send an empty client_shares vector in order to request
 * group selection from the server, at the cost of an additional round
 * trip (see Section 4.1.4).
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8">TLS 1.3 Spec/Section 4.2.8</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public abstract class KeyShareExtensionBase extends Extension {

    @Override
    public final ExtensionType getExtensionType() {
        return ExtensionType.KEY_SHARE;
    }
}

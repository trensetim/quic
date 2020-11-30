package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Server implementation of {@link PreSharedKeyExtensionBase}
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.11">TLS 1.3 Spec/Section 4.2.11</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class PreSharedKeyServerHelloExtension extends PreSharedKeyExtensionBase {

    /**
     * uint16
     * <p/>
     * The server's chosen identity expressed as a
     * (0-based) index into the identities in the client's list.
     *
     * @see PreSharedKeyClientHelloExtension#getIdentities()
     */
    private int selectedIdentity;
}

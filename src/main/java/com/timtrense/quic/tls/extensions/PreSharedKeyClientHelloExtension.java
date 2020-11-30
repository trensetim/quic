package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.PskBinderEntry;
import com.timtrense.quic.tls.PskIdentity;

/**
 * Client implementation of {@link PreSharedKeyExtensionBase}
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.11">TLS 1.3 Spec/Section 4.2.11</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class PreSharedKeyClientHelloExtension extends PreSharedKeyExtensionBase {

    /**
     * A list of the identities that the client is willing to
     * negotiate with the server.  If sent alongside the "early_data"
     * extension (see Section 4.2.10), the first identity is the one used
     * for 0-RTT data.
     * <p/>
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private PskIdentity[] identities = new PskIdentity[0];

    /**
     * A series of HMAC values, one for each value in the
     * identities list and in the same order, computed as described
     * below.
     */
    private PskBinderEntry[] binders = new PskBinderEntry[0];
}

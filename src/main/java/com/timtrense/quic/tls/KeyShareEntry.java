package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <pre>
 *  struct {
 *      NamedGroup group;
 *      opaque key_exchange<1..2^16-1>;
 *  } KeyShareEntry;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8">TLS 1.3 Spec/Section 4.2.8</a>
 */
@Data
public class KeyShareEntry {

    /**
     * The named group for the key being exchanged.
     */
    private NamedGroup group;
    /**
     * Key exchange information.  The contents of this field
     * are determined by the specified group and its corresponding
     * definition.  Finite Field Diffie-Hellman [DH76] parameters are
     * described in Section 4.2.8.1; Elliptic Curve Diffie-Hellman
     * parameters are described in Section 4.2.8.2.
     */
    private byte[] keyExchange;
}

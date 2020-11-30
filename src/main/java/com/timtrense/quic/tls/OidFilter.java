package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <pre>
 * struct {
 *     opaque certificate_extension_oid<1..2^8-1>;
 *     opaque certificate_extension_values<0..2^16-1>;
 * } OIDFilter;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.5">TLS 1.3 Spec/Section 4.2.5</a>
 */
@Data
public class OidFilter {

    private byte[] certificateExtensionOld = new byte[0];
    private byte[] certificateExtensionValues = new byte[0];

}

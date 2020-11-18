package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <pre>
 * struct {
 *         ExtensionType extension_type;
 *         opaque extension_data<0..2^16-1>;
 *     } Extension;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2">TLS 1.3 Spec/Section 4.2</a>
 */
@Data
public abstract class Extension {

    /**
     * @return What type of extension this is
     */
    public abstract ExtensionType getExtensionType();

}

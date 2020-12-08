package com.timtrense.quic.tls;

import java.nio.charset.StandardCharsets;
import lombok.Data;
import lombok.NonNull;

/**
 * OCSP extensions
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc2560">OCS Protocol</a>
 */
@Data
public class OcspExtensions {

    private @NonNull byte[] value;

    public OcspExtensions( @NonNull byte[] value ) {
        this.value = value;
    }

    @Override
    public String toString() {
        return new String( value, StandardCharsets.US_ASCII );
    }
}

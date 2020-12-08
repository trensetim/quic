package com.timtrense.quic.tls;

import java.nio.charset.StandardCharsets;
import lombok.Data;
import lombok.NonNull;

/**
 * An OCSP responder
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc2560">OCS Protocol</a>
 */
@Data
public class OcspResponderId {

    private @NonNull byte[] value;

    /**
     * Converts the given responder id to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param value the hostname to apply. must be ASCII-encodable, must not be null
     */
    public OcspResponderId( @NonNull String value ) {
        this( value.getBytes( StandardCharsets.US_ASCII ) );
    }

    public OcspResponderId( @NonNull byte[] value ) {
        this.value = value;
    }

    /**
     * Converts the given responder id to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param id the id to apply. must be ASCII-encodable, must not be null
     */
    public void setIdByString( @NonNull String id ) {
        this.value = id.getBytes( StandardCharsets.US_ASCII );
    }

    @Override
    public String toString() {
        return new String( value, StandardCharsets.US_ASCII );
    }
}

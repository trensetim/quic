package com.timtrense.quic.tls;

import java.nio.charset.StandardCharsets;
import lombok.Data;
import lombok.NonNull;

/**
 * An application layer protocol name
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc7301#section-3.1">ALPN TLS 1.3 Extension/Section 3.1</a>
 */
@Data
public class ProtocolName {

    private byte[] protocolName;

    /**
     * Converts the given host name to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param protocolName the protocolName to apply. must be ASCII-encodable, must not be null
     */
    public ProtocolName( @NonNull String protocolName ) {
        this( protocolName.getBytes( StandardCharsets.US_ASCII ) );
    }

    public ProtocolName( @NonNull byte[] protocolName ) {
        this.protocolName = protocolName;
    }

    /**
     * Converts the given host name to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param protocolName the protocolName to apply. must be ASCII-encodable, must not be null
     */
    public void setHostnameByString( @NonNull String protocolName ) {
        this.protocolName = protocolName.getBytes( StandardCharsets.US_ASCII );
    }

    @Override
    public String toString() {
        return new String( protocolName, StandardCharsets.US_ASCII );
    }
}

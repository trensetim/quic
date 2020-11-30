package com.timtrense.quic.tls;

import java.nio.charset.StandardCharsets;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

/**
 * A {@link ServerName} that identifies a server via its fully qualified domain name.
 * <p/>
 * <b>"HostName" contains the fully qualified DNS hostname of the server</b>,
 * as understood by the client.  The hostname is represented as a byte
 * string using ASCII encoding without a trailing dot.  This allows the
 * support of internationalized domain names through the use of A-labels
 * defined in [RFC5890].  DNS hostnames are case-insensitive.  The
 * algorithm to compare hostnames is described in [RFC5890], Section
 * 2.3.2.4.
 * <p/>
 * <b>Literal IPv4 and IPv6 addresses are not permitted in "HostName".</b>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-3">TLS 1.3 Extensions Spec/Section 3</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class HostName extends ServerName {

    private @NonNull byte[] value;

    /**
     * Converts the given host name to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param value the hostname to apply. must be ASCII-encodable, must not be null
     */
    public HostName( @NonNull String value ) {
        this( value.getBytes( StandardCharsets.US_ASCII ) );
    }

    public HostName( @NonNull byte[] value ) {
        this.value = value;
    }

    /**
     * Converts the given host name to a byte-array via {@link StandardCharsets#US_ASCII}
     *
     * @param hostname the hostname to apply. must be ASCII-encodable, must not be null
     */
    public void setHostnameByString( @NonNull String hostname ) {
        this.value = hostname.getBytes( StandardCharsets.US_ASCII );
    }

    @Override
    public String toString() {
        return new String( value, StandardCharsets.US_ASCII );
    }
}

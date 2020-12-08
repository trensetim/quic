package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * <pre>
 * enum { ocsp(1), (255) } CertificateStatusType;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-8">TLS 1.3 Extensions Spec/Section 8</a>
 */
public enum CertificateStatusType {

    /**
     * @see <a href="https://tools.ietf.org/html/rfc6960">Online Certificate Status Protocol</a>
     */
    OCSP( 1 )

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    CertificateStatusType( long value ) {this.value = value;}

    public static CertificateStatusType findByValue( int value ) {
        for ( CertificateStatusType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

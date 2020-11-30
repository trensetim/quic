package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * <pre>
 * enum {
 *     X509(0),
 *     RawPublicKey(2),
 *     (255)
 * } CertificateType;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.2">TLS 1.3 Spec/Section 4.4.2</a>
 */
public enum CertificateType {

    X509( 0 ),
    RAW_PUBLIC_KEY( 2 )

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    CertificateType( long value ) {this.value = value;}

    public static CertificateType findByValue( int value ) {
        for ( CertificateType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

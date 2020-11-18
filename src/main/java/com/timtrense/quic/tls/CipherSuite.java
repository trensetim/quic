package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * A symmetric cipher suite defines the pair of the AEAD algorithm and
 * hash algorithm to be used with HKDF.  Cipher suite names follow the
 * naming convention:
 *
 * CipherSuite TLS_AEAD_HASH = VALUE;
 *
 * <pre>
 * +-----------+------------------------------------------------+
 * | Component | Contents                                       |
 * +-----------+------------------------------------------------+
 * | TLS       | The string "TLS"                               |
 * |           |                                                |
 * | AEAD      | The AEAD algorithm used for record protection  |
 * |           |                                                |
 * | HASH      | The hash algorithm used with HKDF              |
 * |           |                                                |
 * | VALUE     | The two-byte ID assigned for this cipher suite |
 * +-----------+------------------------------------------------+
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc8446#appendix-B.4">TLS 1.3 Spec/Appendix B.4</a>
 * @author Tim Trense
 */
public enum CipherSuite {

    TLS_AES_128_GCM_SHA256( (short)0x1301 ),
    TLS_AES_256_GCM_SHA384( (short)0x1302 ),
    TLS_CHACHA20_POLY1305_SHA256( (short)0x1303 ),
    TLS_AES_128_CCM_SHA256( (short)0x1304 ),
    TLS_AES_128_CCM_8_SHA256( (short)0x1305 );

    @Getter
    private final short value;

    CipherSuite( short value ) {this.value = value;}

    public static CipherSuite findByValue( short value ) {
        for ( CipherSuite f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

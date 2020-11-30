package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.9">TLS 1.3 Spec/Section 4.2.9</a>
 */
public enum PskKeyExchangeMode {

    /**
     * PSK-only key establishment.  In this mode, the server
     * MUST NOT supply a "key_share" value.
     */
    PSK_KEY_ESTABLISHMENT( 0 ),
    /**
     * PSK with (EC)DHE key establishment.  In this mode, the
     * client and server MUST supply "key_share" values as described in
     * Section 4.2.8.
     */
    PSK_DHE_KEY_ESTABLISHMENT( 1 ),

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    PskKeyExchangeMode( long value ) {this.value = value;}

    public static PskKeyExchangeMode findByValue( int value ) {
        for ( PskKeyExchangeMode f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

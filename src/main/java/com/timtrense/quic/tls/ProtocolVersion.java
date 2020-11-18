package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * TLS Protocol Version
 *
 * @author Tim Trense
 */
public enum ProtocolVersion {

    // lower values are not supported
    /**
     * TLS 1.2 is not supported by this implementation.
     * This constant solely exists, because in rare situations
     * the specification of the protocol needs an implementation
     * to specify values referring to compatibility.
     */
    TLS_1_2( 0x0303 ),
    /**
     * The TLS 1.3 version that this implementation addresses.
     */
    TLS_1_3( 0x0304 );

    @Getter
    private final long value;

    ProtocolVersion( long value ) {this.value = value;}

    public static ProtocolVersion findByValue( int value ) {
        for ( ProtocolVersion f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

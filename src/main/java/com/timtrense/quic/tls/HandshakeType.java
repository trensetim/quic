package com.timtrense.quic.tls;

import lombok.Getter;

import com.timtrense.quic.FrameType;

/**
 * The handshake protocol is used to negotiate the security parameters
 * of a connection.  Handshake messages are supplied to the TLS record
 * layer, where they are encapsulated within one or more TLSPlaintext or
 * TLSCiphertext structures which are processed and transmitted as
 * specified by the current active connection state.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4">TLS 1.3 Spec/Section 4</a>
 */
public enum HandshakeType {

    CLIENT_HELLO( 1 ),
    SERVER_HELLO( 2 ),
    NEW_SESSION_TICKET( 4 ),
    END_OF_EARLY_DATA( 5 ),
    ENCRYPTED_EXTENSIONS( 8 ),
    CERTIFICATE( 11 ),
    CERTIFICATE_REQUEST( 13 ),
    CERTIFICATE_VERIFY( 15 ),
    FINISHED( 20 ),
    KEY_UPDATE( 24 ),
    MESSAGE_HASH( 254 ),

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    HandshakeType( long value ) {this.value = value;}

    public static HandshakeType findByValue( int value ) {
        for ( HandshakeType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

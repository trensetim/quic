package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * <pre>
 * enum {
 *     update_not_requested(0), update_requested(1), (255)
 * } KeyUpdateRequest;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.6.3">TLS 1.3 Spec/Section 4.6.3</a>
 */
public enum KeyUpdateRequest {

    UPDATE_NOT_REQUESTED( 0 ),
    UPDATE_REQUESTED( 1 )

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    KeyUpdateRequest( long value ) {this.value = value;}

    public static KeyUpdateRequest findByValue( int value ) {
        for ( KeyUpdateRequest f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

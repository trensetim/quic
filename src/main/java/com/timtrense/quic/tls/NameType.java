package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * <b>Currently, the only server names supported are DNS hostnames</b>;
 * however, this does not imply any dependency of TLS on DNS, and other
 * name types may be added in the future (by an RFC that updates this
 * document).  The data structure associated with the host_name NameType
 * is a variable-length vector that begins with a 16-bit length.  For
 * backward compatibility, all future data structures associated with
 * new NameTypes MUST begin with a 16-bit length field.  TLS MAY treat
 * provided server names as opaque data and pass the names and types to
 * the application.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-3">TLS 1.3 Extensions Spec/Section 3</a>
 */
public enum NameType {

    HOST_NAME( 0 )

    // HIGHEST_VALUE( 255 )
    ;

    @Getter
    private final long value;

    NameType( long value ) {this.value = value;}

    public static NameType findByValue( int value ) {
        for ( NameType f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

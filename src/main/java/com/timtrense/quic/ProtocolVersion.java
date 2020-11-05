package com.timtrense.quic;

import lombok.Getter;

/**
 * All known QUIC Protocol Versions
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15">QUIC Spec/Section 15</a>
 */
public enum ProtocolVersion {

    RESERVED_FOR_VERSION_NEGOTIATION( 0x00000000 ),

    /**
     * <quote>
     * uses TLS as a cryptographic handshake protocol
     * </quote>,
     *
     * <quote>
     * The version number for the final version of this specification
     * (0x00000001), is reserved for the version of the protocol that is
     * published as an RFC.
     * </quote>
     */
    ONE( 0x00000001 )

    // more may be added in the future

    ;

    @Getter
    private final int value;

    ProtocolVersion( int value ) {
        this.value = value;
    }

    public static ProtocolVersion findByValue( int value ) {
        for ( ProtocolVersion f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }

    /**
     * Checks whether the given serial constant decodes to a valid usable version for endpoints to
     * communicate with one another
     *
     * @param protocolVersionValue serialized form of the version
     * @return true if that is a {@link ProtocolVersion} that may be used by endpoints
     * with this protocol to communicate
     */
    public static boolean isValid( int protocolVersionValue ) {
        if ( protocolVersionValue == RESERVED_FOR_VERSION_NEGOTIATION.value ) {
            return false;
        }

        // DRAFT QUOTE: Version numbers used to identify IETF drafts are created by adding
        //   the draft number to 0xff000000
        if ( ( protocolVersionValue & 0xff000000 ) == 0xff000000 ) {
            return false;
        }

        // DRAFT QUOTE: Versions that follow the pattern 0x?a?a?a?a are reserved for use in
        //   forcing version negotiation to be exercised
        return ( protocolVersionValue & 0x0a0a0a0a ) != 0x0a0a0a0a;
    }
}

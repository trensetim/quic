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

    GOOGLE_QUIC_44( 0x51303434 ),
    GOOGLE_QUIC_45( 0x51303435 ),
    IETF_DRAFT_11( 0xff00000b ),
    IETF_DRAFT_12( 0xff00000c ),
    IETF_DRAFT_13( 0xff00000d ),
    IETF_DRAFT_14( 0xff00000e ),
    IETF_DRAFT_15( 0xff00000f ),
    IETF_DRAFT_16( 0xff000010 ),
    IETF_DRAFT_17( 0xff000011 ),
    IETF_DRAFT_18( 0xff000012 ),
    IETF_DRAFT_19( 0xff000013 ),
    IETF_DRAFT_20( 0xff000014 ),
    IETF_DRAFT_21( 0xff000015 ),
    IETF_DRAFT_22( 0xff000016 ),
    IETF_DRAFT_23( 0xff000017 ),
    IETF_DRAFT_24( 0xff000018 ),
    IETF_DRAFT_25( 0xff000019 ),
    IETF_DRAFT_26( 0xff00001a ),
    IETF_DRAFT_27( 0xff00001b ),
    IETF_DRAFT_28( 0xff00001c ),
    IETF_DRAFT_29( 0xff00001d ),
    IETF_DRAFT_30( 0xff00001e ),
    IETF_DRAFT_31( 0xff00001f ),
    IETF_DRAFT_32( 0xff000020 ),

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
     * DRAFT QUOTE: Version numbers used to identify IETF drafts are created by adding
     * the draft number to 0xff000000
     *
     * @return true if this version is a draft version from the IETF
     */
    public boolean isIetfDraft() {
        return ( value & 0xff000000 ) == 0xff000000;
    }

    /**
     * DRAFT QUOTE: Version numbers used to identify IETF drafts are created by adding
     * the draft number to 0xff000000
     *
     * @return the draft version from the protocol version or -1 if this is no ietf draft version
     */
    public int getIetfDraftVersion() {
        if ( !isIetfDraft() ) {
            return -1;
        }
        return ( value & 0x00ffffff );
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

        // DRAFT QUOTE: Versions that follow the pattern 0x?a?a?a?a are reserved for use in
        //   forcing version negotiation to be exercised
        return ( protocolVersionValue & 0x0a0a0a0a ) != 0x0a0a0a0a;
    }
}

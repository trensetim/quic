package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * Note: This enum is named "SignatureScheme" because there is already a
 * "SignatureAlgorithm" type in TLS 1.2, which this replaces.  We use
 * the term "signature algorithm" throughout the text.
 *
 * <pre>
 * enum {
 *      unallocated_RESERVED(0x0000),
 *
 *      // Elliptic Curve Groups (ECDHE)
 *      obsolete_RESERVED(0x0001..0x0016),
 *      secp256r1(0x0017),secp384r1(0x0018),secp521r1(0x0019),
 *      obsolete_RESERVED(0x001A..0x001C),
 *      x25519(0x001D),x448(0x001E),
 *
 *      // Finite Field Groups (DHE)
 *      ffdhe2048(0x0100),ffdhe3072(0x0101),ffdhe4096(0x0102),
 *      ffdhe6144(0x0103),ffdhe8192(0x0104),
 *
 *      // Reserved Code Points
 *      ffdhe_private_use(0x01FC..0x01FF),
 *      ecdhe_private_use(0xFE00..0xFEFF),
 *      obsolete_RESERVED(0xFF01..0xFF02),
 *      (0xFFFF)
 * } NamedGroup;
 * </pre>
 *
 * Values within "obsolete_RESERVED" ranges are used in previous
 * versions of TLS and MUST NOT be offered or negotiated by TLS 1.3
 * implementations.  The obsolete curves have various known/theoretical
 * weaknesses or have had very little usage, in some cases only due to
 * unintentional server configuration issues.  They are no longer
 * considered appropriate for general use and should be assumed to be
 * potentially unsafe.  The set of curves specified here is sufficient
 * for interoperability with all currently deployed and properly
 * configured TLS implementations.
 * <p/>
 * <ul>
 *     <li>
 *     Elliptic Curve Groups (ECDHE):  Indicates support for the
 *       corresponding named curve, defined in either FIPS 186-4 [DSS] or
 *       [RFC7748].  Values 0xFE00 through 0xFEFF are reserved for
 *       Private Use [RFC8126].
 *     </li>
 *     <li>
 *     Finite Field Groups (DHE):  Indicates support for the corresponding
 *       finite field group, defined in [RFC7919].  Values 0x01FC through
 *       0x01FF are reserved for Private Use.
 *     </li>
 * </ul>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.7">TLS 1.3 Spec/Section 4.2.7</a>
 */
public enum NamedGroup {

    /* Elliptic Curve Groups (ECDHE) */
    secp256r1( 0x0017 ),
    secp384r1( 0x0018 ),
    secp521r1( 0x0019 ),
    x25519( 0x001D ),
    x448( 0x001E ),

    /* Finite Field Groups (DHE) */
    ffdhe2048( 0x0100 ),
    ffdhe3072( 0x0101 ),
    ffdhe4096( 0x0102 ),
    ffdhe6144( 0x0103 ),
    ffdhe8192( 0x0104 ),

    /* Reserved Code Points */
    //ffdhe_private_use(0x01FC..0x01FF),
    //ecdhe_private_use(0xFE00..0xFEFF)

    // HIGHEST_VALUE( 0xFFFF )
    ;

    @Getter
    private final long value;

    NamedGroup( long value ) {this.value = value;}

    /**
     * determines whether the value indicates an enum constant reserved for "private use ffdhe".
     * <b>Note: The actual enum constants for those values are not fields of this class, but implicitly given</b>
     *
     * @param value the value of an enum constant of this
     * @return true if the value indicates that this constant is for "private use within ffdhe", false otherwise
     */
    public static boolean isFfdhePrivateUse( int value ) {
        return value > 0x01FB && value < 0x0200;
    }

    /**
     * determines whether the value indicates an enum constant reserved for "private use ecdhe".
     * <b>Note: The actual enum constants for those values are not fields of this class, but implicitly given</b>
     *
     * @param value the value of an enum constant of this
     * @return true if the value indicates that this constant is for "private use within ecdhe", false otherwise
     */
    public static boolean isEcdhePrivateUse( int value ) {
        return value > 0xFDFF && value < 0xFF00;
    }

    /**
     * determines whether the value indicates an enum constant reserved for "private use".
     * <b>Note: The actual enum constants for those values are not fields of this class, but implicitly given</b>
     *
     * @param value the value of an enum constant of this
     * @return true if the value indicates that this constant is for "private use", false otherwise
     */
    public static boolean isPrivateUse( int value ) {
        return isFfdhePrivateUse( value ) || isEcdhePrivateUse( value );
    }

    public static NamedGroup findByValue( int value ) {
        for ( NamedGroup f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

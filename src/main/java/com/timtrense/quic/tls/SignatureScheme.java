package com.timtrense.quic.tls;

import lombok.Getter;

/**
 * Note: This enum is named "SignatureScheme" because there is already a
 * "SignatureAlgorithm" type in TLS 1.2, which this replaces.  We use
 * the term "signature algorithm" throughout the text.
 *
 * <pre>
 * enum {
 *      // RSASSA-PKCS1-v1_5 algorithms
 *      rsa_pkcs1_sha256(0x0401),
 *      rsa_pkcs1_sha384(0x0501),
 *      rsa_pkcs1_sha512(0x0601),
 *
 *      // ECDSA algorithms
 *      ecdsa_secp256r1_sha256(0x0403),
 *      ecdsa_secp384r1_sha384(0x0503),
 *      ecdsa_secp521r1_sha512(0x0603),
 *
 *      // RSASSA-PSS algorithms with public key OID rsaEncryption
 *      rsa_pss_rsae_sha256(0x0804),
 *      rsa_pss_rsae_sha384(0x0805),
 *      rsa_pss_rsae_sha512(0x0806),
 *
 *      // EdDSA algorithms
 *      ed25519(0x0807),
 *      ed448(0x0808),
 *
 *      // RSASSA-PSS algorithms with public key OID RSASSA-PSS
 *      rsa_pss_pss_sha256(0x0809),
 *      rsa_pss_pss_sha384(0x080a),
 *      rsa_pss_pss_sha512(0x080b),
 *
 *      // Legacy algorithms
 *      rsa_pkcs1_sha1(0x0201),
 *      ecdsa_sha1(0x0203),
 *
 *      // Reserved Code Points
 *      private_use(0xFE00..0xFFFF),
 *      (0xFFFF)
 * } SignatureScheme;
 * </pre>
 * <p/>
 * <b> The code point groups listed above have the
 * following meanings:</b>
 * <ul>
 *     <li>
 *     RSASSA-PKCS1-v1_5 algorithms:  Indicates a signature algorithm using
 *       RSASSA-PKCS1-v1_5 [RFC8017] with the corresponding hash algorithm
 *       as defined in [SHS].  These values refer solely to signatures
 *       which appear in certificates (see Section 4.4.2.2) and are not
 *       defined for use in signed TLS handshake messages, although they
 *       MAY appear in "signature_algorithms" and
 *       "signature_algorithms_cert" for backward compatibility with
 *       TLS 1.2.
 *     </li>
 *     <li>
 *     ECDSA algorithms:  Indicates a signature algorithm using ECDSA
 *       [ECDSA], the corresponding curve as defined in ANSI X9.62 [ECDSA]
 *       and FIPS 186-4 [DSS], and the corresponding hash algorithm as
 *       defined in [SHS].  The signature is represented as a DER-encoded
 *       [X690] ECDSA-Sig-Value structure.
 *     </li>
 *     <li>
 *     RSASSA-PSS RSAE algorithms:  Indicates a signature algorithm using
 *       RSASSA-PSS [RFC8017] with mask generation function 1.  The digest
 *       used in the mask generation function and the digest being signed
 *       are both the corresponding hash algorithm as defined in [SHS].
 *       The length of the Salt MUST be equal to the length of the output
 *       of the digest algorithm.  If the public key is carried in an X.509
 *       certificate, it MUST use the rsaEncryption OID [RFC5280].
 *     </li>
 *     <li>
 *     EdDSA algorithms:  Indicates a signature algorithm using EdDSA as
 *       defined in [RFC8032] or its successors.  Note that these
 *       correspond to the "PureEdDSA" algorithms and not the "prehash"
 *       variants.
 *     </li>
 *     <li>
 *     RSASSA-PSS PSS algorithms:  Indicates a signature algorithm using
 *       RSASSA-PSS [RFC8017] with mask generation function 1.  The digest
 *       used in the mask generation function and the digest being signed
 *       are both the corresponding hash algorithm as defined in [SHS].
 *       The length of the Salt MUST be equal to the length of the digest
 *       algorithm.  If the public key is carried in an X.509 certificate,
 *       it MUST use the RSASSA-PSS OID [RFC5756].  When used in
 *       certificate signatures, the algorithm parameters MUST be DER
 *       encoded.  If the corresponding public key's parameters are
 *       present, then the parameters in the signature MUST be identical to
 *       those in the public key.
 *     </li>
 *     <li>
 *     Legacy algorithms:  Indicates algorithms which are being deprecated
 *       because they use algorithms with known weaknesses, specifically
 *       SHA-1 which is used in this context with either (1) RSA using
 *       RSASSA-PKCS1-v1_5 or (2) ECDSA.  These values refer solely to
 *       signatures which appear in certificates (see Section 4.4.2.2) and
 *       are not defined for use in signed TLS handshake messages, although
 *       they MAY appear in "signature_algorithms" and
 *       "signature_algorithms_cert" for backward compatibility with
 *       TLS 1.2.  Endpoints SHOULD NOT negotiate these algorithms but are
 *       permitted to do so solely for backward compatibility.  Clients
 *       offering these values MUST list them as the lowest priority
 *       (listed after all other algorithms in SignatureSchemeList).
 *       TLS 1.3 servers MUST NOT offer a SHA-1 signed certificate unless
 *       no valid certificate chain can be produced without it (see
 *       Section 4.4.2.2).
 *     </li>
 * </ul>
 * <p/>
 * The signatures on certificates that are self-signed or certificates
 * that are trust anchors are not validated, since they begin a
 * certification path (see [RFC5280], Section 3.2).  A certificate that
 * begins a certification path MAY use a signature algorithm that is not
 * advertised as being supported in the "signature_algorithms"
 * extension.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.3">TLS 1.3 Spec/Section 4.2.3</a>
 */
public enum SignatureScheme {

    /* RSASSA-PKCS1-v1_5 algorithms */
    RSA_PKCS1_SHA256( 0x0401 ),
    RSA_PKCS1_SHA384( 0x0501 ),
    RSA_PKCS1_SHA512( 0x0601 ),

    /* ECDSA algorithms */
    ECDSA_SECP256R1_SHA256( 0x0403 ),
    ECDSA_SECP384R1_SHA384( 0x0503 ),
    ECDSA_SECP521R1_SHA512( 0x0603 ),

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RSA_PSS_RSAE_SHA256( 0x0804 ),
    RSA_PSS_RSAE_SHA384( 0x0805 ),
    RSA_PSS_RSAE_SHA512( 0x0806 ),

    /* EdDSA algorithms */
    ED25519( 0x0807 ),
    ED448( 0x0808 ),

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RSA_PSS_PSS_SHA256( 0x0809 ),
    RSA_PSS_PSS_SHA384( 0x080a ),
    RSA_PSS_PSS_SHA512( 0x080b ),

    /* Legacy algorithms */
    RSA_PKCS1_SHA1( 0x0201 ),
    ECDSA_SHA1( 0x0203 ),

    /* Reserved Code Points */
    // PRIVATE_USE( 0xFE00..0xFFFF)

    // HIGHEST_VALUE( 0xFFFF )
    ;

    @Getter
    private final long value;

    SignatureScheme( long value ) {this.value = value;}

    /**
     * determines whether the value indicates an enum constant reserved for "private use".
     * <b>Note: The actual enum constants for those values are not fields of this class, but implicitly given</b>
     *
     * @param value the value of an enum constant of this
     * @return true if the value indicates that this constant is for "private use", false otherwise
     */
    public static boolean isPrivateUse( int value ) {
        return value > 0xFDFF && value < 0x10000;
    }

    public static SignatureScheme findByValue( int value ) {
        for ( SignatureScheme f : values() ) {
            if ( f.value == value ) {
                return f;
            }
        }
        return null;
    }
}

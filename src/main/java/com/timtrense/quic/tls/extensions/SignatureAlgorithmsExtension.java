package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.SignatureScheme;

/**
 * <pre>
 * struct {
 *     SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 * </pre>
 *
 * TLS 1.3 provides two extensions for indicating which signature
 * algorithms may be used in digital signatures.  The
 * "signature_algorithms_cert" extension applies to signatures in
 * certificates, and the "signature_algorithms" extension, which
 * originally appeared in TLS 1.2, applies to signatures in
 * CertificateVerify messages.  The keys found in certificates MUST also
 * be of appropriate type for the signature algorithms they are used
 * with.  This is a particular issue for RSA keys and PSS signatures, as
 * described below.  If no "signature_algorithms_cert" extension is
 * present, then the "signature_algorithms" extension also applies to
 * signatures appearing in certificates.  Clients which desire the
 * server to authenticate itself via a certificate MUST send the
 * "signature_algorithms" extension.  If a server is authenticating via
 * a certificate and the client has not sent a "signature_algorithms"
 * extension, then the server MUST abort the handshake with a
 * "missing_extension" alert (see Section 9.2).
 * <p/>
 * The "signature_algorithms_cert" extension was added to allow
 * implementations which supported different sets of algorithms for
 * certificates and in TLS itself to clearly signal their capabilities.
 * TLS 1.2 implementations SHOULD also process this extension.
 * Implementations which have the same policy in both cases MAY omit the
 * "signature_algorithms_cert" extension.
 * <p/>
 * The "extension_data" field of these extensions contains a
 * SignatureSchemeList value: {@link SignatureScheme}.
 * Note: This enum is named "SignatureScheme" because there is already a
 * "SignatureAlgorithm" type in TLS 1.2, which this replaces.  We use
 * the term "signature algorithm" throughout the text.
 * <p/>
 * Each SignatureScheme value lists a single signature algorithm that
 * the client is willing to verify.  The values are indicated in
 * descending order of preference.  Note that a signature algorithm
 * takes as input an arbitrary-length message, rather than a digest.
 * Algorithms which traditionally act on a digest should be defined in
 * TLS to first hash the input with a specified hash algorithm and then
 * proceed as usual.
 * <p/>
 * The signatures on certificates that are self-signed or certificates
 * that are trust anchors are not validated, since they begin a
 * certification path (see [RFC5280], Section 3.2).  A certificate that
 * begins a certification path MAY use a signature algorithm that is not
 * advertised as being supported in the "signature_algorithms"
 * extension.
 * <p/>
 * <b>Note that TLS 1.2 defines this extension differently.  TLS 1.3
 * implementations willing to negotiate TLS 1.2 MUST behave in
 * accordance with the requirements of [RFC5246] when negotiating that
 * version.  In particular:</b>
 * <ul>
 *     <li>
 *         TLS 1.2 ClientHellos MAY omit this extension.
 *     </li>
 *     <li>
 *       In TLS 1.2, the extension contained hash/signature pairs.  The
 *       pairs are encoded in two octets, so SignatureScheme values have
 *       been allocated to align with TLS 1.2's encoding.  Some legacy
 *       pairs are left unallocated.  These algorithms are deprecated as of
 *       TLS 1.3.  They MUST NOT be offered or negotiated by any
 *       implementation.  In particular, MD5 [SLOTH], SHA-224, and DSA
 *       MUST NOT be used.
 *     </li>
 *     <li>
 *       ECDSA signature schemes align with TLS 1.2's ECDSA hash/signature
 *       pairs.  However, the old semantics did not constrain the signing
 *       curve.  If TLS 1.2 is negotiated, implementations MUST be prepared
 *       to accept a signature that uses any curve that they advertised in
 *       the "supported_groups" extension.
 *     </li>
 *     <li>
 *       Implementations that advertise support for RSASSA-PSS (which is
 *       mandatory in TLS 1.3) MUST be prepared to accept a signature using
 *       that scheme even when TLS 1.2 is negotiated.  In TLS 1.2,
 *       RSASSA-PSS is used with RSA cipher suites.
 *     </li>
 * </ul>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.3">TLS 1.3 Spec/Section 4.2.3</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class SignatureAlgorithmsExtension extends Extension {

    /**
     * <b>Implementation Note: this field will be set to an empty array upon instantiation</b>
     */
    private @NonNull SignatureScheme[] supportedSignatureAlgorithms = new SignatureScheme[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SIGNATURE_ALGORITHMS;
    }
}

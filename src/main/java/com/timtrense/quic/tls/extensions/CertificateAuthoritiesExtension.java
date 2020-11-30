package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * <pre>
 * struct {
 *     DistinguishedName authorities<3..2^16-1>;
 * } CertificateAuthoritiesExtension;
 * </pre>
 *
 * The "certificate_authorities" extension is used to indicate the
 * certificate authorities (CAs) which an endpoint supports and which
 * SHOULD be used by the receiving endpoint to guide certificate
 * selection.
 * <p/>
 * The client MAY send the "certificate_authorities" extension in the
 * ClientHello message.  The server MAY send it in the
 * CertificateRequest message.
 * <p/>
 * The "trusted_ca_keys" extension [RFC6066], which serves a similar
 * purpose but is more complicated, is not used in TLS 1.3 (although it
 * may appear in ClientHello messages from clients which are offering
 * prior versions of TLS).
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.4">TLS 1.3 Spec/Section 4.2.4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class CertificateAuthoritiesExtension extends Extension {

    /**
     * <pre>
     * // opaque == 1 single uninterpreted byte
     * opaque DistinguishedName<1..2^16-1>;
     *
     * struct {
     *     DistinguishedName authorities<3..2^16-1>;
     * } CertificateAuthoritiesExtension;
     * </pre>
     * <p/>
     * A list of the distinguished names [X501] of acceptable
     * certificate authorities, represented in DER-encoded [X690] format.
     * These distinguished names specify a desired distinguished name for
     * a trust anchor or subordinate CA; thus, this message can be used
     * to describe known trust anchors as well as a desired authorization
     * space.
     */
    private @NonNull byte[][] authorities = new byte[0][];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SIGNATURE_ALGORITHMS;
    }
}

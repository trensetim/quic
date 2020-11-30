package com.timtrense.quic.tls;

import lombok.Data;

/**
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.2">TLS 1.3 Spec/Section 4.4.2</a>
 */
@Data
public class CertificateEntry {

    /**
     * the type of the certificate
     */
    private CertificateType certificateType;
    /**
     * depending on the type one of the following:
     * <pre>
     * select (certificate_type) {
     *    case RawPublicKey:
     *        // From RFC 7250 ASN.1_subjectPublicKeyInfo
     *        opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
     *    case X509:
     *        opaque cert_data<1..2^24-1>;
     * };
     * </pre>
     */
    private byte[] certificateData = new byte[0];
    /**
     * A set of extension values for the CertificateEntry.  The
     * "Extension" format is defined in Section 4.2.  Valid extensions
     * for server certificates at present include the OCSP Status
     * extension [RFC6066] and the SignedCertificateTimestamp extension
     * [RFC6962]; future extensions may be defined for this message as
     * well.  Extensions in the Certificate message from the server MUST
     * correspond to ones from the ClientHello message.  Extensions in
     * the Certificate message from the client MUST correspond to
     * extensions in the CertificateRequest message from the server.  If
     * an extension applies to the entire chain, it SHOULD be included in
     * the first CertificateEntry.
     */
    private Extension[] extensions = new Extension[0];
}

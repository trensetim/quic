package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.CertificateEntry;
import com.timtrense.quic.tls.HandshakeType;

/**
 * This message conveys the endpoint's certificate chain to the peer.
 * <p/>
 * The server MUST send a Certificate message whenever the agreed-upon
 * key exchange method uses certificates for authentication (this
 * includes all key exchange methods defined in this document
 * except PSK).
 * <p/>
 * The client MUST send a Certificate message if and only if the server
 * has requested client authentication via a CertificateRequest message
 * (Section 4.3.2).  If the server requests client authentication but no
 * suitable certificate is available, the client MUST send a Certificate
 * message containing no certificates (i.e., with the "certificate_list"
 * field having length 0).  A Finished message MUST be sent regardless
 * of whether the Certificate message is empty.
 * <p/>
 * Structure of this message:
 * <pre>
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     CertificateEntry certificate_list<0..2^24-1>;
 * } Certificate;
 * </pre>
 * <p/>
 * If the corresponding certificate type extension
 * ("server_certificate_type" or "client_certificate_type") was not
 * negotiated in EncryptedExtensions, or the X.509 certificate type was
 * negotiated, then each CertificateEntry contains a DER-encoded X.509
 * certificate.  The sender's certificate MUST come in the first
 * CertificateEntry in the list.  Each following certificate SHOULD
 * directly certify the one immediately preceding it.  Because
 * certificate validation requires that trust anchors be distributed
 * independently, a certificate that specifies a trust anchor MAY be
 * omitted from the chain, provided that supported peers are known to
 * possess any omitted certificates.
 * <p/>
 * Note: Prior to TLS 1.3, "certificate_list" ordering required each
 * certificate to certify the one immediately preceding it; however,
 * some implementations allowed some flexibility.  Servers sometimes
 * send both a current and deprecated intermediate for transitional
 * purposes, and others are simply configured incorrectly, but these
 * cases can nonetheless be validated properly.  For maximum
 * compatibility, all implementations SHOULD be prepared to handle
 * potentially extraneous certificates and arbitrary orderings from any
 * TLS version, with the exception of the end-entity certificate which
 * MUST be first.
 * <p/>
 * If the RawPublicKey certificate type was negotiated, then the
 * certificate_list MUST contain no more than one CertificateEntry,
 * which contains an ASN1_subjectPublicKeyInfo value as defined in
 * [RFC7250], Section 3.
 * <p/>
 * The OpenPGP certificate type [RFC6091] MUST NOT be used with TLS 1.3.
 * <p/>
 * The server's certificate_list MUST always be non-empty.  A client
 * will send an empty certificate_list if it does not have an
 * appropriate certificate to send in response to the server's
 * authentication request.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.2">TLS 1.3 Spec/Section 4.4.2</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class Certificate extends AuthenticationMessage {

    /**
     * If this message is in response to a
     * CertificateRequest, the value of certificate_request_context in
     * that message.  Otherwise (in the case of server authentication),
     * this field SHALL be zero length.
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private byte[] certificateRequestContext = new byte[0];

    /**
     * A sequence (chain) of CertificateEntry structures,
     * each containing a single certificate and set of extensions.
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private CertificateEntry[] certificateList = new CertificateEntry[0];

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.CERTIFICATE;
    }
}

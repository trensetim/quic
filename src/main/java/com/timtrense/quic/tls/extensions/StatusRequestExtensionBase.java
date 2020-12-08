package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.CertificateStatusType;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * Constrained clients may wish to use a certificate-status protocol
 * such as OCSP [RFC2560] to check the validity of server certificates,
 * in order to avoid transmission of CRLs and therefore save bandwidth
 * on constrained networks.  This extension allows for such information
 * to be sent in the TLS handshake, saving roundtrips and resources.
 * <p/>
 * In order to indicate their desire to receive certificate status
 * information, clients MAY include an extension of type
 * "status_request" in the (extended) client hello.  The
 * "extension_data" field of this extension SHALL contain
 * "CertificateStatusRequest" where:
 *
 * <pre>
 * struct {
 *     CertificateStatusType status_type;
 *     select (status_type) {
 *         case ocsp: OCSPStatusRequest;
 *     } request;
 * } CertificateStatusRequest;
 *
 * enum { ocsp(1), (255) } CertificateStatusType;
 *
 * struct {
 *     ResponderID responder_id_list<0..2^16-1>;
 *     Extensions  request_extensions;
 * } OCSPStatusRequest;
 *
 * opaque ResponderID<1..2^16-1>;
 * opaque Extensions<0..2^16-1>;
 * </pre>
 *
 * In the OCSPStatusRequest, the "ResponderIDs" provides a list of OCSP
 * responders that the client trusts.  A zero-length "responder_id_list"
 * sequence has the special meaning that the responders are implicitly
 * known to the server, e.g., by prior arrangement.  "Extensions" is a
 * DER encoding of OCSP request extensions.
 * <p/>
 * Both "ResponderID" and "Extensions" are DER-encoded ASN.1 types as
 * defined in [RFC2560].  "Extensions" is imported from [RFC5280].  A
 * zero-length "request_extensions" value means that there are no
 * extensions (as opposed to a zero-length ASN.1 SEQUENCE, which is not
 * valid for the "Extensions" type).
 * <p/>
 * In the case of the "id-pkix-ocsp-nonce" OCSP extension, [RFC2560] is
 * unclear about its encoding; for clarification, the nonce MUST be a
 * DER-encoded OCTET STRING, which is encapsulated as another OCTET
 * STRING (note that implementations based on an existing OCSP client
 * will need to be checked for conformance to this requirement).
 * <p/>
 * Servers that receive a client hello containing the "status_request"
 * extension MAY return a suitable certificate status response to the
 * client along with their certificate.  If OCSP is requested, they
 * SHOULD use the information contained in the extension when selecting
 * an OCSP responder and SHOULD include request_extensions in the OCSP
 * request.
 * <p/>
 * Servers return a certificate response along with their certificate by
 * sending a "CertificateStatus" message immediately after the
 * "Certificate" message (and before any "ServerKeyExchange" or
 * "CertificateRequest" messages).  If a server returns a
 * "CertificateStatus" message, then the server MUST have included an
 * extension of type "status_request" with empty "extension_data" in the
 * extended server hello.  The "CertificateStatus" message is conveyed
 * using the handshake message type "certificate_status" as follows (see
 * also Section 2):
 *
 * <pre>
 * struct {
 *     CertificateStatusType status_type;
 *     select (status_type) {
 *         case ocsp: OCSPResponse;
 *     } response;
 * } CertificateStatus;
 *
 * opaque OCSPResponse<1..2^24-1>;
 * </pre>
 *
 * An "ocsp_response" contains a complete, DER-encoded OCSP response
 * (using the ASN.1 type OCSPResponse defined in [RFC2560]).  Only one
 * OCSP response may be sent.
 * <p/>
 * Note that a server MAY also choose not to send a "CertificateStatus"
 * message, even if has received a "status_request" extension in the
 * client hello message and has sent a "status_request" extension in the
 * server hello message.
 * <p/>
 * Note in addition that a server MUST NOT send the "CertificateStatus"
 * message unless it received a "status_request" extension in the client
 * hello message and sent a "status_request" extension in the server
 * hello message.
 * <p/>
 * Clients requesting an OCSP response and receiving an OCSP response in
 * a "CertificateStatus" message MUST check the OCSP response and abort
 * the handshake if the response is not satisfactory with
 * bad_certificate_status_response(113) alert.  This alert is always
 * fatal.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-8">TLS 1.3 Extensions Spec/Section 8</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class StatusRequestExtensionBase extends Extension {

    private CertificateStatusType statusType;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.STATUS_REQUEST;
    }
}

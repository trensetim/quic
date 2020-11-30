package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.OidFilter;

/**
 * <pre>
 * struct {
 *     OIDFilter filters<0..2^16-1>;
 * } OIDFilterExtension;
 * </pre>
 *
 * The "oid_filters" extension allows servers to provide a set of
 * OID/value pairs which it would like the client's certificate to
 * match.  This extension, if provided by the server, MUST only be sent
 * in the CertificateRequest message.
 * <p/>
 * PKIX RFCs define a variety of certificate extension OIDs and their
 * corresponding value types.  Depending on the type, matching
 * certificate extension values are not necessarily bitwise-equal.  It
 * is expected that TLS implementations will rely on their PKI libraries
 * to perform certificate selection using certificate extension OIDs.
 * <p/>
 * This document defines matching rules for two standard certificate
 * extensions defined in [RFC5280]:
 * <ul>
 *     <li>
 *     The Key Usage extension in a certificate matches the request when
 *       all key usage bits asserted in the request are also asserted in
 *       the Key Usage certificate extension.
 *     </li>
 *     <li>
 *     The Extended Key Usage extension in a certificate matches the
 *       request when all key purpose OIDs present in the request are also
 *       found in the Extended Key Usage certificate extension.  The
 *       special anyExtendedKeyUsage OID MUST NOT be used in the request.
 *     </li>
 * </ul>
 * Separate specifications may define matching rules for other
 *    certificate extensions.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.5">TLS 1.3 Spec/Section 4.2.5</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class OidFilterExtension extends Extension {

    /**
     * A list of certificate extension OIDs [RFC5280] with their
     * allowed value(s) and represented in DER-encoded [X690] format.
     * Some certificate extension OIDs allow multiple values (e.g.,
     * Extended Key Usage).  If the server has included a non-empty
     * filters list, the client certificate included in the response MUST
     * contain all of the specified extension OIDs that the client
     * recognizes.  For each extension OID recognized by the client, all
     * of the specified values MUST be present in the client certificate
     * (but the certificate MAY have other values as well).  However, the
     * client MUST ignore and skip any unrecognized certificate extension
     * OIDs.  If the client ignored some of the required certificate
     * extension OIDs and supplied a certificate that does not satisfy
     * the request, the server MAY at its discretion either continue the
     * connection without client authentication or abort the handshake
     * with an "unsupported_certificate" alert.  Any given OID MUST NOT
     * appear more than once in the filters list.
     */
    private OidFilter[] filters = new OidFilter[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.OID_FILTERS;
    }
}

package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.CertificateStatusType;
import com.timtrense.quic.tls.OcspExtensions;
import com.timtrense.quic.tls.OcspResponderId;

/**
 * @author Tim Trense
 * @see StatusRequestExtensionBase
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class StatusRequestOcspExtension extends StatusRequestExtensionBase {

    /**
     * In the OCSPStatusRequest, the "ResponderIDs" provides a list of OCSP
     * responders that the client trusts.  A zero-length "responder_id_list"
     * sequence has the special meaning that the responders are implicitly
     * known to the server, e.g., by prior arrangement.
     */
    private OcspResponderId[] responderIdList;
    /**
     * "Extensions" is a DER encoding of OCSP request extensions.
     *
     * A zero-length "request_extensions" value means that there are no
     * extensions (as opposed to a zero-length ASN.1 SEQUENCE, which is not
     * valid for the "Extensions" type).
     */
    private OcspExtensions requestExtensions;

    public StatusRequestOcspExtension() {
        setStatusType( CertificateStatusType.OCSP );
    }
}

package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.ExtendedHandshake;
import com.timtrense.quic.tls.HandshakeType;

/**
 * A server which is authenticating with a certificate MAY optionally
 * request a certificate from the client.  This message, if sent, MUST
 * follow EncryptedExtensions.
 * <p/>
 * Structure of this message:
 * <pre>
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     Extension extensions<2..2^16-1>;
 * } CertificateRequest;
 * </pre>
 * In prior versions of TLS, the CertificateRequest message carried a
 * list of signature algorithms and certificate authorities which the
 * server would accept.  In TLS 1.3, the former is expressed by sending
 * the "signature_algorithms" and optionally "signature_algorithms_cert"
 * extensions.  The latter is expressed by sending the
 * "certificate_authorities" extension (see Section 4.2.4).
 * <p/>
 * Servers which are authenticating with a PSK MUST NOT send the
 * CertificateRequest message in the main handshake, though they MAY
 * send it in post-handshake authentication (see Section 4.6.2) provided
 * that the client has sent the "post_handshake_auth" extension (see
 * Section 4.2.6).
 * <p/>
 * <b>contained extensions:</b>
 * A set of extensions describing the parameters of the
 * certificate being requested.  The "signature_algorithms" extension
 * MUST be specified, and other extensions may optionally be included
 * if defined for this message.  Clients MUST ignore unrecognized
 * extensions.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.3.2">TLS 1.3 Spec/Section 4.3.2</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class CertificateRequest extends ExtendedHandshake {

    /**
     * An opaque string which identifies the
     * certificate request and which will be echoed in the client's
     * Certificate message.  The certificate_request_context MUST be
     * unique within the scope of this connection (thus preventing replay
     * of client CertificateVerify messages).  This field SHALL be zero
     * length unless used for the post-handshake authentication exchanges
     * described in Section 4.6.2.  When requesting post-handshake
     * authentication, the server SHOULD make the context unpredictable
     * to the client (e.g., by randomly generating it) in order to
     * prevent an attacker who has temporary access to the client's
     * private key from pre-computing valid CertificateVerify messages.
     */
    private byte[] certificateRequestContext = new byte[0];

    /*
    extensions: see super, see class javadoc
     */

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.CERTIFICATE_REQUEST;
    }
}

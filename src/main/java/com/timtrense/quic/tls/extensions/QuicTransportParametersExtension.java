package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.impl.base.TransportParameterCollection;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * QUIC transport parameters are carried in a TLS extension.  Different
 * versions of QUIC might define a different method for negotiating
 * transport configuration.
 * <p/>
 * Including transport parameters in the TLS handshake provides
 * integrity protection for these values.
 * <p/>
 * The extension_data field of the quic_transport_parameters extension
 * contains a value that is defined by the version of QUIC that is in
 * use.
 * <p/>
 * The quic_transport_parameters extension is carried in the ClientHello
 * and the EncryptedExtensions messages during the handshake.  Endpoints
 * MUST send the quic_transport_parameters extension; endpoints that
 * receive ClientHello or EncryptedExtensions messages without the
 * quic_transport_parameters extension MUST close the connection with an
 * error of type 0x16d (equivalent to a fatal TLS missing_extension
 * alert, see Section 4.8).
 * <p/>
 * While the transport parameters are technically available prior to the
 * completion of the handshake, they cannot be fully trusted until the
 * handshake completes, and reliance on them should be minimized.
 * However, any tampering with the parameters will cause the handshake
 * to fail.
 * <p/>
 * Endpoints MUST NOT send this extension in a TLS connection that does
 * not use QUIC (such as the use of TLS with TCP defined in [TLS13]).  A
 * fatal unsupported_extension alert MUST be sent by an implementation
 * that supports this extension if the extension is received when the
 * transport is not QUIC.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-8.2">QUIC TLS Spec/Section 8.2</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class QuicTransportParametersExtension extends Extension {

    /**
     * TODO: find structural definition of this extension
     */
    private TransportParameterCollection transportParameters;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.QUIC_TRANSPORT_PARAMETERS;
    }
}

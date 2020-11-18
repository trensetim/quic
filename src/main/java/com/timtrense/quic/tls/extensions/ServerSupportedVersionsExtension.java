package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.ProtocolVersion;

/**
 * For details see {@link ClientSupportedVersionsExtension}
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.1">TLS 1.3 Spec/Section 4.2.1</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ServerSupportedVersionsExtension extends Extension {

    private ProtocolVersion selectedVersion;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SUPPORTED_VERSIONS;
    }
}

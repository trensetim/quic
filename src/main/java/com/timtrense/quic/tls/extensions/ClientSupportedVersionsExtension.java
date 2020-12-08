package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.ProtocolVersion;

/**
 * @author Tim Trense
 * @see SupportedVersionsExtensionBase
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ClientSupportedVersionsExtension extends SupportedVersionsExtensionBase {

    private ProtocolVersion[] versions;
}

package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.ProtocolVersion;

/**
 * @author Tim Trense
 * @see SupportedVersionsExtensionBase
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ServerSupportedVersionsExtension extends SupportedVersionsExtensionBase {

    private ProtocolVersion selectedVersion;
}

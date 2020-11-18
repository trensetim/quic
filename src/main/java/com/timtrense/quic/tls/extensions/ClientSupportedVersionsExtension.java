package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.ProtocolVersion;

/**
 * <pre>
 * struct {
 *       select (Handshake.msg_type) {
 *           case client_hello:
 *                ProtocolVersion versions<2..254>;
 *
 *           case server_hello:
 *                ProtocolVersion selected_version;
 *      };
 * } SupportedVersions;
 * </pre>
 * The "supported_versions" extension is used by the client to indicate
 * which versions of TLS it supports and by the server to indicate which
 * version it is using.  The extension contains a list of supported
 * versions in preference order, with the most preferred version first.
 * Implementations of this specification MUST send this extension in the
 * ClientHello containing all versions of TLS which they are prepared to
 * negotiate (for this specification, that means minimally 0x0304, but
 * if previous versions of TLS are allowed to be negotiated, they MUST
 * be present as well).
 * <p/>
 * If this extension is not present, servers which are compliant with
 * this specification and which also support TLS 1.2 MUST negotiate
 * TLS 1.2 or prior as specified in [RFC5246], even if
 * ClientHello.legacy_version is 0x0304 or later.  Servers MAY abort the
 * handshake upon receiving a ClientHello with legacy_version 0x0304 or
 * later.
 * <p/>
 * If this extension is present in the ClientHello, servers MUST NOT use
 * the ClientHello.legacy_version value for version negotiation and MUST
 * use only the "supported_versions" extension to determine client
 * preferences.  Servers MUST only select a version of TLS present in
 * that extension and MUST ignore any unknown versions that are present
 * in that extension.  Note that this mechanism makes it possible to
 * negotiate a version prior to TLS 1.2 if one side supports a sparse
 * range.  Implementations of TLS 1.3 which choose to support prior
 * versions of TLS SHOULD support TLS 1.2.  Servers MUST be prepared to
 * receive ClientHellos that include this extension but do not include
 * 0x0304 in the list of versions.
 * <p/>
 * A server which negotiates a version of TLS prior to TLS 1.3 MUST set
 * ServerHello.version and MUST NOT send the "supported_versions"
 * extension.  A server which negotiates TLS 1.3 MUST respond by sending
 * a "supported_versions" extension containing the selected version
 * value (0x0304).  It MUST set the ServerHello.legacy_version field to
 * 0x0303 (TLS 1.2).  Clients MUST check for this extension prior to
 * processing the rest of the ServerHello (although they will have to
 * parse the ServerHello in order to read the extension).
 *
 * If this extension is present, clients MUST ignore the
 * ServerHello.legacy_version value and MUST use only the
 * "supported_versions" extension to determine the selected version.  If
 * the "supported_versions" extension in the ServerHello contains a
 * version not offered by the client or contains a version prior to
 * TLS 1.3, the client MUST abort the handshake with an
 * "illegal_parameter" alert.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.1">TLS 1.3 Spec/Section 4.2.1</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ClientSupportedVersionsExtension extends Extension {

    private ProtocolVersion[] versions;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SUPPORTED_VERSIONS;
    }
}

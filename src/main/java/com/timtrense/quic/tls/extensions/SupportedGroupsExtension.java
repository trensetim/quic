package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.NamedGroup;

/**
 * When sent by the client, the "supported_groups" extension indicates
 * the named groups which the client supports for key exchange, ordered
 * from most preferred to least preferred.
 * configured TLS implementations.
 * <p/>
 * Note: In versions of TLS prior to TLS 1.3, this extension was named
 * "elliptic_curves" and only contained elliptic curve groups.  See
 * [RFC8422] and [RFC7919].  This extension was also used to negotiate
 * ECDSA curves.  Signature algorithms are now negotiated independently
 * (see Section 4.2.3).
 * <p/>
 * Items in named_group_list are ordered according to the sender's
 * preferences (most preferred choice first).
 * <p/>
 * As of TLS 1.3, servers are permitted to send the "supported_groups"
 * extension to the client.  Clients MUST NOT act upon any information
 * found in "supported_groups" prior to successful completion of the
 * handshake but MAY use the information learned from a successfully
 * completed handshake to change what groups they use in their
 * "key_share" extension in subsequent connections.  If the server has a
 * group it prefers to the ones in the "key_share" extension but is
 * still willing to accept the ClientHello, it SHOULD send
 * "supported_groups" to update the client's view of its preferences;
 * this extension SHOULD contain all groups the server supports,
 * regardless of whether they are currently supported by the client.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.7">TLS 1.3 Spec/Section 4.2.7</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class SupportedGroupsExtension extends Extension {

    /**
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private @NonNull NamedGroup[] namedGroupList = new NamedGroup[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SUPPORTED_GROUPS;
    }
}

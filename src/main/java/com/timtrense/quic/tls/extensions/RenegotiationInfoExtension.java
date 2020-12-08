package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * This document defines a new TLS extension, "renegotiation_info" (with
 * extension type 0xff01), which contains a cryptographic binding to the
 * enclosing TLS connection (if any) for which the renegotiation is
 * being performed.  The "extension data" field of this extension
 * contains a "RenegotiationInfo" structure:
 * <pre>
 * struct {
 *    opaque renegotiated_connection<0..255>;
 * } RenegotiationInfo;
 * </pre>
 * The contents of this extension are specified as follows.
 * <ul>
 *     <li>
 *         If this is the initial handshake for a connection, then the
 *       "renegotiated_connection" field is of zero length in both the
 *       ClientHello and the ServerHello.  Thus, the entire encoding of the
 *       extension is ff 01 00 01 00.  The first two octets represent the
 *       extension type, the third and fourth octets the length of the
 *       extension itself, and the final octet the zero length byte for the
 *       "renegotiated_connection" field.
 *     </li>
 *     <li>
 *         For ClientHellos that are renegotiating, this field contains the
 *       "client_verify_data" specified in Section 3.1.
 *     </li>
 *     <li>
 *         For ServerHellos that are renegotiating, this field contains the
 *       concatenation of client_verify_data and server_verify_data.  For
 *       current versions of TLS, this will be a 24-byte value (for SSLv3,
 *       it will be a 72-byte value).
 *     </li>
 * </ul>
 * This extension also can be used with Datagram TLS (DTLS) [RFC4347].
 *    Although, for editorial simplicity, this document refers to TLS, all
 *    requirements in this document apply equally to DTLS.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc5746#section-3.2">
 * TLS 1.3 Extension Renegotiation Info Spec/Section 3.2</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class RenegotiationInfoExtension extends Extension {

    /**
     * <b>Implementation Note: the field will be set to null upon instantiation</b>
     */
    private byte[] renegotiatedConnection=new byte[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.RENEGOTIATION_INFO;
    }
}

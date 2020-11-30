package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.ProtocolName;

/**
 * A new extension type ("application_layer_protocol_negotiation(16)")
 * is defined and MAY be included by the client in its "ClientHello"
 * message.
 * <p/>
 * The "extension_data" field of the
 * ("application_layer_protocol_negotiation(16)") extension SHALL
 * contain a "ProtocolNameList" value.
 * <p/>
 * <pre>
 * opaque ProtocolName<1..2^8-1>;
 *
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 * </pre>
 * <p/>
 * Servers that receive a ClientHello containing the
 * "application_layer_protocol_negotiation" extension MAY return a
 * suitable protocol selection response to the client.  The server will
 * ignore any protocol name that it does not recognize. <b> A new
 * ServerHello extension type
 * ("application_layer_protocol_negotiation(16)") MAY be returned to the
 * client within the extended ServerHello message.  The "extension_data"
 * field of the ("application_layer_protocol_negotiation(16)") extension
 * is structured the same as described above for the client
 * "extension_data", except that the "ProtocolNameList" MUST contain
 * exactly one "ProtocolName". </b>
 * <p/>
 * Therefore, a full handshake with the
 * "application_layer_protocol_negotiation" extension in the ClientHello
 * and ServerHello messages has the following flow (contrast with
 * Section 7.3 of [RFC5246]):
 * <pre>
 *    Client                                              Server
 *
 *    ClientHello                     -------->       ServerHello
 *      (ALPN extension &                               (ALPN extension &
 *       list of protocols)                              selected protocol)
 *                                                    Certificate*
 *                                                    ServerKeyExchange*
 *                                                    CertificateRequest*
 *                                    <--------       ServerHelloDone
 *    Certificate*
 *    ClientKeyExchange
 *    CertificateVerify*
 *    [ChangeCipherSpec]
 *    Finished                        -------->
 *                                                    [ChangeCipherSpec]
 *                                    <--------       Finished
 *    Application Data                <------->       Application Data
 *
 *                                  Figure 1
 *
 *    * Indicates optional or situation-dependent messages that are not
 *    always sent.
 * </pre>
 * An abbreviated handshake with the
 * "application_layer_protocol_negotiation" extension has the following
 * flow:
 * <pre>
 *    Client                                              Server
 *
 *    ClientHello                     -------->       ServerHello
 *      (ALPN extension &                               (ALPN extension &
 *       list of protocols)                              selected protocol)
 *                                                    [ChangeCipherSpec]
 *                                    <--------       Finished
 *    [ChangeCipherSpec]
 *    Finished                        -------->
 *    Application Data                <------->       Application Data
 *
 *                                  Figure 2
 * </pre>
 * <p/>
 * Unlike many other TLS extensions, this extension does not establish
 * properties of the session, only of the connection.  When session
 * resumption or session tickets [RFC5077] are used, the previous
 * contents of this extension are irrelevant, and only the values in the
 * new handshake messages are considered.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc7301#section-3.1">TLS App-Layer Protocol Negotiation Ext/Section 3.1</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ApplicationLayerProtocolNegotiationExtension extends Extension {

    /**
     * "ProtocolNameList" contains the list of protocols advertised by the
     * client, in descending order of preference.  Protocols are named by
     * IANA-registered, opaque, non-empty byte strings, as described further
     * in Section 6 ("IANA Considerations") of this document.  Empty strings
     * MUST NOT be included and byte strings MUST NOT be truncated.
     * <p/>
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private ProtocolName[] protocolNameList = new ProtocolName[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
    }
}

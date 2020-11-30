package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.ServerName;

/**
 * TLS does not provide a mechanism for a client to tell a server the
 * name of the server it is contacting.  It may be desirable for clients
 * to provide this information to facilitate secure connections to
 * servers that host multiple 'virtual' servers at a single underlying
 * network address.
 * <p/>
 * In order to provide any of the server names, clients MAY include an
 * extension of type "server_name" in the (extended) client hello.  The
 * "extension_data" field of this extension SHALL contain
 * "ServerNameList" where:
 * <pre>
 * struct {
 *     NameType name_type;
 *     select (name_type) {
 *         case host_name: HostName;
 *     } name;
 * } ServerName;
 *
 * enum {
 *     host_name(0), (255)
 * } NameType;
 *
 * opaque HostName<1..2^16-1>;
 *
 * struct {
 *     ServerName server_name_list<1..2^16-1>
 * } ServerNameList;
 * </pre>
 * The ServerNameList MUST NOT contain more than one name of the same
 * name_type.  If the server understood the ClientHello extension but
 * does not recognize the server name, the server SHOULD take one of two
 * actions: either abort the handshake by sending a fatal-level
 * unrecognized_name(112) alert or continue the handshake.  It is NOT
 * RECOMMENDED to send a warning-level unrecognized_name(112) alert,
 * because the client's behavior in response to warning-level alerts is
 * unpredictable.  If there is a mismatch between the server name used
 * by the client application and the server name of the credential
 * chosen by the server, this mismatch will become apparent when the
 * client application performs the server endpoint identification, at
 * which point the client application will have to decide whether to
 * proceed with the communication.  TLS implementations are encouraged
 * to make information available to application callers about warning-
 * level alerts that were received or sent during a TLS handshake.  Such
 * information can be useful for diagnostic purposes.
 * <br/>
 * Note: Earlier versions of this specification permitted multiple
 * names of the same name_type.  In practice, current client
 * implementations only send one name, and the client cannot
 * necessarily find out which name the server selected.  Multiple
 * names of the same name_type are therefore now prohibited.
 * <p/>
 * It is RECOMMENDED that clients include an extension of type
 * "server_name" in the client hello whenever they locate a server by a
 * supported name type.
 * <p/>
 * A server that receives a client hello containing the "server_name"
 * extension MAY use the information contained in the extension to guide
 * its selection of an appropriate certificate to return to the client,
 * and/or other aspects of security policy.  In this event, the server
 * SHALL include an extension of type "server_name" in the (extended)
 * server hello.  The "extension_data" field of this extension SHALL be
 * empty.
 * <p/>
 * When the server is deciding whether or not to accept a request to
 * resume a session, the contents of a server_name extension MAY be used
 * in the lookup of the session in the session cache.  The client SHOULD
 * include the same server_name extension in the session resumption
 * request as it did in the full handshake that established the session.
 * A server that implements this extension MUST NOT accept the request
 * to resume the session if the server_name extension contains a
 * different name.  Instead, it proceeds with a full handshake to
 * establish a new session.  When resuming a session, the server MUST
 * NOT include a server_name extension in the server hello.
 * <p/>
 * If an application negotiates a server name using an application
 * protocol and then upgrades to TLS, and if a server_name extension is
 * sent, then the extension SHOULD contain the same name that was
 * negotiated in the application protocol.  If the server_name is
 * established in the TLS session handshake, the client SHOULD NOT
 * attempt to request a different server name at the application layer.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-3">TLS 1.3 Extensions Spec/Section 3</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class ServerNameIndicationExtension extends Extension {

    /**
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private ServerName[] serverNameList = new ServerName[0];

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.SERVER_NAME;
    }
}

package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <pre>
 * struct {
 *     HandshakeType msg_type;
 *     uint24 length; // remaining bytes in message
 *     select(Handshake.msg_type){
 *         case client_hello:ClientHello;
 *         case server_hello:ServerHello;
 *         case end_of_early_data:EndOfEarlyData;
 *         case encrypted_extensions:EncryptedExtensions;
 *         case certificate_request:CertificateRequest;
 *         case certificate:Certificate;
 *         case certificate_verify:CertificateVerify;
 *         case finished:Finished;
 *         case new_session_ticket:NewSessionTicket;
 *         case key_update:KeyUpdate;
 *     };
 * } Handshake;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4">TLS 1.3 Spec/Section 4</a>
 */
@Data
public abstract class Handshake {

    /**
     * @return What type of handshake message this is
     */
    public abstract HandshakeType getMessageType();

    /**
     * Remaining bytes in message as a 3-byte unsigned integer
     * <p/>
     * <b>Implementation Note: the field will be set to zero upon instantiation</b>
     */
    private int length;
}

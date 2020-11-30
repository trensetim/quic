package com.timtrense.quic.tls.handshake;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.ExtendedHandshake;
import com.timtrense.quic.tls.Handshake;
import com.timtrense.quic.tls.HandshakeType;
import com.timtrense.quic.tls.SignatureScheme;

/**
 * This message is used to provide explicit proof that an endpoint
 * possesses the private key corresponding to its certificate.  The
 * CertificateVerify message also provides integrity for the handshake
 * up to this point.  Servers MUST send this message when authenticating
 * via a certificate.  Clients MUST send this message whenever
 * authenticating via a certificate (i.e., when the Certificate message
 * is non-empty).  When sent, this message MUST appear immediately after
 * the Certificate message and immediately prior to the Finished
 * message.
 * <p/>
 * Structure of this message:
 * <pre>
 * struct {
 *    SignatureScheme algorithm;
 *    opaque signature<0..2^16-1>;
 * } CertificateVerify;
 * </pre>
 * The algorithm field specifies the signature algorithm used (see
 * Section 4.2.3 for the definition of this type).  The signature is a
 * digital signature using that algorithm.  The content that is covered
 * under the signature is the hash output as described in Section 4.4.1,
 * namely:
 * <pre>
 *     Transcript-Hash(Handshake Context, Certificate)
 * </pre>
 * The digital signature is then computed over the concatenation of:
 * <ul>
 *     <li>
 *         A string that consists of octet 32 (0x20) repeated 64 times
 *     </li>
 *     <li>
 *         The context string
 *     </li>
 *     <li>
 *         A single 0 byte which serves as the separator
 *     </li>
 *     <li>
 *         The content to be signed
 *     </li>
 * </ul>
 * This structure is intended to prevent an attack on previous versions
 * of TLS in which the ServerKeyExchange format meant that attackers
 * could obtain a signature of a message with a chosen 32-byte prefix
 * (ClientHello.random).  The initial 64-byte pad clears that prefix
 * along with the server-controlled ServerHello.random.
 * <p/>
 * The context string for a server signature is
 * "TLS 1.3, server CertificateVerify".  The context string for a
 * client signature is "TLS 1.3, client CertificateVerify".  It is
 * used to provide separation between signatures made in different
 * contexts, helping against potential cross-protocol attacks.
 * <p/>
 * For example, if the transcript hash was 32 bytes of 01 (this length
 * would make sense for SHA-256), the content covered by the digital
 * signature for a server CertificateVerify would be:
 * <pre>
 *    2020202020202020202020202020202020202020202020202020202020202020
 *    2020202020202020202020202020202020202020202020202020202020202020
 *    544c5320312e332c207365727665722043657274696669636174655665726966
 *    79
 *    00
 *    0101010101010101010101010101010101010101010101010101010101010101
 * </pre>
 * On the sender side, the process for computing the signature field of
 * the CertificateVerify message takes as input:
 * <ul>
 *     <li>
 *         The content covered by the digital signature
 *     </li>
 *     <li>
 *         The private signing key corresponding to the certificate sent in
 *           the previous message
 *     </li>
 * </ul>
 * If the CertificateVerify message is sent by a server, the signature
 * algorithm MUST be one offered in the client's "signature_algorithms"
 * extension unless no valid certificate chain can be produced without
 * unsupported algorithms (see Section 4.2.3).
 * <p/>
 * If sent by a client, the signature algorithm used in the signature
 * MUST be one of those present in the supported_signature_algorithms
 * field of the "signature_algorithms" extension in the
 * CertificateRequest message.
 * <p/>
 * In addition, the signature algorithm MUST be compatible with the key
 * in the sender's end-entity certificate.  RSA signatures MUST use an
 * RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5
 * algorithms appear in "signature_algorithms".  The SHA-1 algorithm
 * MUST NOT be used in any signatures of CertificateVerify messages.
 * <p/>
 * All SHA-1 signature algorithms in this specification are defined
 * solely for use in legacy certificates and are not valid for
 * CertificateVerify signatures.
 * <p/>
 * The receiver of a CertificateVerify message MUST verify the signature
 * field.  The verification process takes as input:
 * <ul>
 *     <li>
 *         The content covered by the digital signature
 *     </li>
 *     <li>
 *         The public key contained in the end-entity certificate found in
 *       the associated Certificate message
 *     </li>
 *     <li>
 *         The digital signature received in the signature field of the
 *       CertificateVerify message
 *     </li>
 * </ul>
 * If the verification fails, the receiver MUST terminate the handshake
 * with a "decrypt_error" alert.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.4.3">TLS 1.3 Spec/Section 4.4.3</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class CertificateVerify extends Handshake {

    private SignatureScheme algorithm;
    /**
     * <b>Implementation Note: the field will be initialized to an empty array upon instantiation</b>
     */
    private byte[] signature = new byte[0];

    @Override
    public HandshakeType getMessageType() {
        return HandshakeType.CERTIFICATE_VERIFY;
    }
}

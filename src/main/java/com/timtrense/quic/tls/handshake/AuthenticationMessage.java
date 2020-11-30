package com.timtrense.quic.tls.handshake;

import com.timtrense.quic.tls.Handshake;

/**
 * Common base class for messages from
 * <a href="https://tools.ietf.org/html/rfc8446#section-4.4">Section 4.4 "Authentication Messages"</a>
 * of the TLS 1.3 Specification.
 *
 * <p/>
 * As discussed in Section 2, TLS generally uses a common set of
 * messages for authentication, key confirmation, and handshake
 * integrity: Certificate, CertificateVerify, and Finished.  (The PSK
 * binders also perform key confirmation, in a similar fashion.)  These
 * three messages are always sent as the last messages in their
 * handshake flight.  The Certificate and CertificateVerify messages are
 * only sent under certain circumstances, as defined below.  The
 * Finished message is always sent as part of the Authentication Block.
 * These messages are encrypted under keys derived from the
 * [sender]_handshake_traffic_secret.
 * <p/>
 * The computations for the Authentication messages all uniformly take
 * the following inputs:
 * <ul>
 *     <li>
 *         The certificate and signing key to be used.
 *     </li>
 *     <li>
 *         A Handshake Context consisting of the set of messages to be
 *       included in the transcript hash.
 *     </li>
 *     <li>
 *         A Base Key to be used to compute a MAC key.
 *     </li>
 * </ul>
 * <p/>
 * Based on these inputs, the messages then contain:
 * <ul>
 *     <li>
 *         {@link Certificate}:  The certificate to be used for authentication, and any
 *       supporting certificates in the chain.  Note that certificate-based
 *       client authentication is not available in PSK handshake flows
 *       (including 0-RTT).
 *     </li>
 *     <li>
 *         {@link CertificateVerify}:  A signature over the value
 *       Transcript-Hash(Handshake Context, Certificate).
 *     </li>
 *     <li>
 *         {@link Finished}:  A MAC over the value Transcript-Hash(Handshake Context,
 *       Certificate, CertificateVerify) using a MAC key derived from the
 *       Base Key.
 *     </li>
 * </ul>
 * <p/>
 * The following table defines the Handshake Context and MAC Base Key
 * for each scenario:
 * <pre>
 *    +-----------+-------------------------+-----------------------------+
 *    | Mode      | Handshake Context       | Base Key                    |
 *    +-----------+-------------------------+-----------------------------+
 *    | Server    | ClientHello ... later   | server_handshake_traffic_   |
 *    |           | of EncryptedExtensions/ | secret                      |
 *    |           | CertificateRequest      |                             |
 *    |           |                         |                             |
 *    | Client    | ClientHello ... later   | client_handshake_traffic_   |
 *    |           | of server               | secret                      |
 *    |           | Finished/EndOfEarlyData |                             |
 *    |           |                         |                             |
 *    | Post-     | ClientHello ... client  | client_application_traffic_ |
 *    | Handshake | Finished +              | secret_N                    |
 *    |           | CertificateRequest      |                             |
 *    +-----------+-------------------------+-----------------------------+
 * </pre>
 *
 * @author Tim Trense
 */
public abstract class AuthenticationMessage extends Handshake {
}

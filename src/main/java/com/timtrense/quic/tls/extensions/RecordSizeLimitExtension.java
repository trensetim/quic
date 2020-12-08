package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * <h2>Limitations of the "max_fragment_length" Extension</h2>
 * The "max_fragment_length" extension has several limitations that make
 * it unsuitable for use.
 *
 * A client that has no constraints preventing it from accepting a large
 * record cannot use "max_fragment_length" without risking a reduction
 * in the size of records.  The maximum value that the extension permits
 * is 2^12, much smaller than the maximum record size of 2^14 that the
 * protocol permits.
 *
 * For large data transfers, small record sizes can materially affect
 * performance.  Every record incurs additional costs, both in the
 * additional octets for record headers and for expansion due to
 * encryption.  Processing more records also adds computational
 * overheads that can be amortized more effectively for larger record
 * sizes.  Consequently, clients that are capable of receiving large
 * records could be unwilling to risk reducing performance by offering
 * the extension, especially if the extension is rarely needed.
 *
 * This would not be an issue if a codepoint were available or could be
 * added for fragments of 2^14 octets.  However, RFC 6066 requires that
 * servers abort the handshake with an "illegal_parameter" alert if they
 * receive the extension with a value they don't understand.  This makes
 * it impossible to add new values to the extension without the risk of
 * failed connection attempts.
 *
 * A server that negotiates "max_fragment_length" is required to echo
 * the value selected by the client.  The server cannot request a lower
 * limit than the one the client offered.  This is a significant problem
 * if a server is more constrained than the clients it serves.
 *
 * The "max_fragment_length" extension is also ill-suited to cases where
 * the capabilities of client and server are asymmetric.  Constraints on
 * record size are often receiver constraints.
 *
 * In comparison, an implementation might be able to send data
 * incrementally.  Encryption does not have the same atomicity
 * requirement.  Some ciphers can be encrypted and sent progressively.
 * Thus, an endpoint might be willing to send records larger than the
 * limit it advertises for records that it receives.
 *
 * If these disincentives are sufficient to discourage clients from
 * deploying the "max_fragment_length" extension, then constrained
 * servers are unable to limit record sizes.
 *
 * <h2>The "record_size_limit" Extension</h2>
 * The ExtensionData of the "record_size_limit" extension is
 * RecordSizeLimit:
 * <pre>
 * uint16 RecordSizeLimit;
 * </pre>
 * The value of RecordSizeLimit is the maximum size of record in octets
 * that the endpoint is willing to receive.  This value is used to limit
 * the size of records that are created when encoding application data
 * and the protected handshake message into records.
 *
 * When the "record_size_limit" extension is negotiated, an endpoint
 * MUST NOT generate a protected record with plaintext that is larger
 * than the RecordSizeLimit value it receives from its peer.
 * Unprotected messages are not subject to this limit.
 *
 * This value is the length of the plaintext of a protected record.  The
 * value includes the content type and padding added in TLS 1.3 (that
 * is, the complete length of TLSInnerPlaintext).  In TLS 1.2 and
 * earlier, the limit covers all input to compression and encryption
 * (that is, the data that ultimately produces TLSCiphertext.fragment).
 * Padding added as part of encryption, such as that added by a block
 * cipher, is not included in this count (see Section 4.1).
 *
 * An endpoint that supports all record sizes can include any limit up
 * to the protocol-defined limit for maximum record size.  For TLS 1.2
 * and earlier, that limit is 2^14 octets.  TLS 1.3 uses a limit of
 * 2^14+1 octets.  Higher values are currently reserved for future
 * versions of the protocol that may allow larger records; an endpoint
 * MUST NOT send a value higher than the protocol-defined maximum record
 * size unless explicitly allowed by such a future version or extension.
 * A server MUST NOT enforce this restriction; a client might advertise
 * a higher limit that is enabled by an extension or version the server
 * does not understand.  A client MAY abort the handshake with an
 * "illegal_parameter" alert if the record_size_limit extension includes
 * a value greater than the maximum record size permitted by the
 * negotiated protocol version and extensions.
 *
 * Even if a larger record size limit is provided by a peer, an endpoint
 * MUST NOT send records larger than the protocol-defined limit, unless
 * explicitly allowed by a future TLS version or extension.
 *
 * The record size limit only applies to records sent toward the
 * endpoint that advertises the limit.  An endpoint can send records
 * that are larger than the limit it advertises as its own limit.  A TLS
 * endpoint that receives a record larger than its advertised limit MUST
 * generate a fatal "record_overflow" alert; a DTLS endpoint that
 * receives a record larger than its advertised limit MAY either
 * generate a fatal "record_overflow" alert or discard the record.
 *
 * Endpoints SHOULD advertise the "record_size_limit" extension, even if
 * they have no need to limit the size of records.  For clients, this
 * allows servers to advertise a limit at their discretion.  For
 * servers, this allows clients to know that their limit will be
 * respected.  If this extension is not negotiated, endpoints can send
 * records of any size permitted by the protocol or other negotiated
 * extensions.
 *
 * Endpoints MUST NOT send a "record_size_limit" extension with a value
 * smaller than 64.  An endpoint MUST treat receipt of a smaller value
 * as a fatal error and generate an "illegal_parameter" alert.
 *
 * In TLS 1.3, the server sends the "record_size_limit" extension in the
 * EncryptedExtensions message.
 *
 * During renegotiation or resumption, the record size limit is
 * renegotiated.  Records are subject to the limits that were set in the
 * handshake that produces the keys that are used to protect those
 * records.  This admits the possibility that the extension might not be
 * negotiated when a connection is renegotiated or resumed.
 *
 * The Path Maximum Transmission Unit (PMTU) in DTLS also limits the
 * size of records.  The record size limit does not affect PMTU
 * discovery and SHOULD be set independently.  The record size limit is
 * fixed during the handshake and so should be set based on constraints
 * at the endpoint and not based on the current network environment.  In
 * comparison, the PMTU is determined by the network path and can change
 * dynamically over time.  See [PMTU] and Section 4.1.1.1 of [DTLS] for
 * more detail on PMTU discovery.
 *
 * PMTU governs the size of UDP datagrams, which limits the size of
 * records, but does not prevent records from being smaller.  An
 * endpoint that sends small records is still able to send multiple
 * records in a single UDP datagram.
 *
 * <h2>Record Expansion Limits</h2>
 * The size limit expressed in the "record_size_limit" extension doesn't
 * account for expansion due to compression or record protection.  It is
 * expected that a constrained device will disable compression to avoid
 * unpredictable increases in record size.  Stream ciphers and existing
 * AEAD ciphers don't permit variable amounts of expansion, but block
 * ciphers do permit variable expansion.
 *
 * In TLS 1.2, block ciphers allow from 1 to 256 octets of padding.
 * When a limit lower than the protocol-defined limit is advertised, a
 * second limit applies to the length of records that use block ciphers.
 * An endpoint MUST NOT add padding to records that would cause the
 * protected record to exceed the size of a protected record that
 * contains the maximum amount of plaintext and the minimum permitted
 * amount of padding.
 *
 * For example, TLS_RSA_WITH_AES_128_CBC_SHA has 16-octet blocks and a
 * 20-octet MAC.  Given a record size limit of 256, a record of that
 * length would require a minimum of 11 octets of padding (for
 * [RFC5246], where the MAC is covered by encryption); or 15 octets if
 * the "encrypt_then_mac" extension [RFC7366] is negotiated.  With this
 * limit, a record with 250 octets of plaintext could be padded to the
 * same length by including at most 17 octets of padding, or 21 octets
 * with "encrypt_then_mac".
 *
 * An implementation that always adds the minimum amount of padding will
 * always comply with this requirement.
 *
 * <h2>Deprecating "max_fragment_length"</h2>
 * The "record_size_limit" extension replaces the "max_fragment_length"
 * extension [RFC6066].  A server that supports the "record_size_limit"
 * extension MUST ignore a "max_fragment_length" that appears in a
 * ClientHello if both extensions appear.  A client MUST treat receipt
 * of both "max_fragment_length" and "record_size_limit" as a fatal
 * error, and it SHOULD generate an "illegal_parameter" alert.
 *
 * Clients that depend on having a small record size MAY continue to
 * advertise the "max_fragment_length".
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8449">RFC 8449</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class RecordSizeLimitExtension extends Extension {

    /**
     * The value of RecordSizeLimit is the maximum size of record in octets
     * that the endpoint is willing to receive.  This value is used to limit
     * the size of records that are created when encoding application data
     * and the protected handshake message into records.
     */
    private int recordSizeLimit;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.RECORD_SIZE_LIMIT;
    }
}

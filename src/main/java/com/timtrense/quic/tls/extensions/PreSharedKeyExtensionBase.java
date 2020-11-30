package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;

/**
 * The "pre_shared_key" extension is used to negotiate the identity of
 * the pre-shared key to be used with a given handshake in association
 * with PSK key establishment.
 * <p/>
 * The "extension_data" field of this extension contains a
 * "PreSharedKeyExtension" value:
 * <pre>
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *     PskIdentity identities<7..2^16-1>;
 *     PskBinderEntry binders<33..2^16-1>;
 * } OfferedPsks;
 *
 * struct {
 *     select (Handshake.msg_type) {
 *         case client_hello: OfferedPsks;
 *         case server_hello: uint16 selected_identity;
 *     };
 * } PreSharedKeyExtension;
 * </pre>
 *
 * Each PSK is associated with a single Hash algorithm.  For PSKs
 * established via the ticket mechanism (Section 4.6.1), this is the KDF
 * Hash algorithm on the connection where the ticket was established.
 * For externally established PSKs, the Hash algorithm MUST be set when
 * the PSK is established or default to SHA-256 if no such algorithm is
 * defined.  The server MUST ensure that it selects a compatible PSK
 * (if any) and cipher suite.
 * <p/>
 * In TLS versions prior to TLS 1.3, the Server Name Identification
 * (SNI) value was intended to be associated with the session (Section 3
 * of [RFC6066]), with the server being required to enforce that the SNI
 * value associated with the session matches the one specified in the
 * resumption handshake.  However, in reality the implementations were
 * not consistent on which of two supplied SNI values they would use,
 * leading to the consistency requirement being de facto enforced by the
 * clients.  In TLS 1.3, the SNI value is always explicitly specified in
 * the resumption handshake, and there is no need for the server to
 * associate an SNI value with the ticket.  Clients, however, SHOULD
 * store the SNI with the PSK to fulfill the requirements of
 * Section 4.6.1.
 * <p/>
 * Implementor's note: When session resumption is the primary use case
 * of PSKs, the most straightforward way to implement the PSK/cipher
 * suite matching requirements is to negotiate the cipher suite first
 * and then exclude any incompatible PSKs.  Any unknown PSKs (e.g., ones
 * not in the PSK database or encrypted with an unknown key) SHOULD
 * simply be ignored.  If no acceptable PSKs are found, the server
 * SHOULD perform a non-PSK handshake if possible.  If backward
 * compatibility is important, client-provided, externally established
 * PSKs SHOULD influence cipher suite selection.
 * <p/>
 * Prior to accepting PSK key establishment, the server MUST validate
 * the corresponding binder value (see Section 4.2.11.2 below).  If this
 * value is not present or does not validate, the server MUST abort the
 * handshake.  Servers SHOULD NOT attempt to validate multiple binders;
 * rather, they SHOULD select a single PSK and validate solely the
 * binder that corresponds to that PSK.  See Section 8.2 and
 * Appendix E.6 for the security rationale for this requirement.  In
 * order to accept PSK key establishment, the server sends a
 * "pre_shared_key" extension indicating the selected identity.
 * <p/>
 * Clients MUST verify that the server's selected_identity is within the
 * range supplied by the client, that the server selected a cipher suite
 * indicating a Hash associated with the PSK, and that a server
 * "key_share" extension is present if required by the ClientHello
 * "psk_key_exchange_modes" extension.  If these values are not
 * consistent, the client MUST abort the handshake with an
 * "illegal_parameter" alert.
 * <p/>
 * If the server supplies an "early_data" extension, the client MUST
 * verify that the server's selected_identity is 0.  If any other value
 * is returned, the client MUST abort the handshake with an
 * "illegal_parameter" alert.
 * <p/>
 * The "pre_shared_key" extension MUST be the last extension in the
 * ClientHello (this facilitates implementation as described below).
 * Servers MUST check that it is the last extension and otherwise fail
 * the handshake with an "illegal_parameter" alert.
 * <p/>
 * <h2>Ticket Age</h2>
 * The client's view of the age of a ticket is the time since the
 * receipt of the NewSessionTicket message.  Clients MUST NOT attempt to
 * use tickets which have ages greater than the "ticket_lifetime" value
 * which was provided with the ticket.  The "obfuscated_ticket_age"
 * field of each PskIdentity contains an obfuscated version of the
 * ticket age formed by taking the age in milliseconds and adding the
 * "ticket_age_add" value that was included with the ticket (see
 * Section 4.6.1), modulo 2^32.  This addition prevents passive
 * observers from correlating connections unless tickets are reused.
 * Note that the "ticket_lifetime" field in the NewSessionTicket message
 * is in seconds but the "obfuscated_ticket_age" is in milliseconds.
 * Because ticket lifetimes are restricted to a week, 32 bits is enough
 * to represent any plausible age, even in milliseconds.
 * <p/>
 * <h2>Processing Order</h2>
 * Clients are permitted to "stream" 0-RTT data until they receive the
 * server's Finished, only then sending the EndOfEarlyData message,
 * followed by the rest of the handshake.  In order to avoid deadlocks,
 * when accepting "early_data", servers MUST process the client's
 * ClientHello and then immediately send their flight of messages,
 * rather than waiting for the client's EndOfEarlyData message before
 * sending its ServerHello.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.11">TLS 1.3 Spec/Section 4.2.11</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public abstract class PreSharedKeyExtensionBase extends Extension {

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.PRE_SHARED_KEY;
    }
}

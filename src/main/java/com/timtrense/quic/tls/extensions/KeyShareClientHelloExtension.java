package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.KeyShareEntry;

/**
 * In the ClientHello message, the "extension_data" field of this
 * extension contains a "KeyShareClientHello" value:
 *
 * <pre>
 * struct {
 *     KeyShareEntry client_shares<0..2^16-1>;
 * } KeyShareClientHello;
 * </pre>
 *
 * This vector MAY be empty if the client is requesting a
 * HelloRetryRequest.  Each KeyShareEntry value MUST correspond to a
 * group offered in the "supported_groups" extension and MUST appear in
 * the same order.  However, the values MAY be a non-contiguous subset
 * of the "supported_groups" extension and MAY omit the most preferred
 * groups.  Such a situation could arise if the most preferred groups
 * are new and unlikely to be supported in enough places to make
 * pregenerating key shares for them efficient.
 * <p/>
 * Clients can offer as many KeyShareEntry values as the number of
 * supported groups it is offering, each representing a single set of
 * key exchange parameters.  For instance, a client might offer shares
 * for several elliptic curves or multiple FFDHE groups.  The
 * key_exchange values for each KeyShareEntry MUST be generated
 * independently.  Clients MUST NOT offer multiple KeyShareEntry values
 * for the same group.  Clients MUST NOT offer any KeyShareEntry values
 * for groups not listed in the client's "supported_groups" extension.
 * Servers MAY check for violations of these rules and abort the
 * handshake with an "illegal_parameter" alert if one is violated.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.8">TLS 1.3 Spec/Section 4.2.8</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class KeyShareClientHelloExtension extends KeyShareExtensionBase {

    /**
     * A list of offered KeyShareEntry values in descending
     * order of client preference.
     * <p/>
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private KeyShareEntry[] clientShares = new KeyShareEntry[0];

}

package com.timtrense.quic.tls;

import lombok.Data;

/**
 * <pre>
 * struct {
 *     opaque identity<1..2^16-1>;
 *     uint32 obfuscated_ticket_age;
 * } PskIdentity;
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.11">TLS 1.3 Spec/Section 4.2.11</a>
 */
@Data
public class PskIdentity {

    /**
     * A label for a key.  For instance, a ticket (as defined in
     * Appendix B.3.4) or a label for a pre-shared key established
     * externally.
     * <p/>
     * <b>Implementation Note: the field will be set to an empty array upon instantiation</b>
     */
    private byte[] identity = new byte[0];

    /**
     * uint32
     * <p/>
     * An obfuscated version of the age of the key.
     * Section 4.2.11.1 describes how to form this value for identities
     * established via the NewSessionTicket message.  For identities
     * established externally, an obfuscated_ticket_age of 0 SHOULD be
     * used, and servers MUST ignore the value.
     */
    private long obfuscatedTicketAge;
}

package com.timtrense.quic;

import lombok.Getter;

/**
 * <pre>
 *     +======+===========+================+
 *     | Type | Name      | Section        |
 *     +======+===========+================+
 *     |  0x0 | Initial   | Section 17.2.2 |
 *     +------+-----------+----------------+
 *     |  0x1 | 0-RTT     | Section 17.2.3 |
 *     +------+-----------+----------------+
 *     |  0x2 | Handshake | Section 17.2.4 |
 *     +------+-----------+----------------+
 *     |  0x3 | Retry     | Section 17.2.5 |
 *     +------+-----------+----------------+
 * </pre>
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-17.2">QUIC Spec/Section 17.2</a>
 */
public enum LongHeaderPacketType {

    INITIAL( 0x00 ),
    ZERO_RTT( 0x01 ),
    HANDSHAKE( 0x02 ),
    RETRY( 0x03 );

    @Getter
    private final int id;

    LongHeaderPacketType( int id ) {
        this.id = id;
    }

    public static LongHeaderPacketType findById( int value ) {
        for ( LongHeaderPacketType f : values() ) {
            if ( f.id == value ) {
                return f;
            }
        }
        return null;
    }
}

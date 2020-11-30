package com.timtrense.quic.tls;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;

/**
 * This class gives {@link Handshake}-Messages which contain {@link Extension extensions} a common base
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4">TLS 1.3 Spec/Section 4</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public abstract class ExtendedHandshake extends Handshake {

    /**
     * A mutable list of {@link Extension extensions} registered with this message.
     * <p/>
     * <b>Implementation Note: the field will be initialized with an
     * {@link ArrayList} of initial size 6 upon instantiation</b>
     */
    private @NonNull List<Extension> extensions =
            new ArrayList<>( 6 /*server hello min size for extensions*/ );

}

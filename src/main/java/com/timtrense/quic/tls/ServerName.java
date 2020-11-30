package com.timtrense.quic.tls;

import lombok.Data;
import lombok.NonNull;

/**
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc6066#section-3">TLS 1.3 Extensions Spec/Section 3</a>
 */
@Data
public abstract class ServerName {

    /**
     * <b>Implementation Note: the field is initialized to {@link NameType#HOST_NAME} which is implemented in
     * {@link HostName}</b>
     */
    private final @NonNull NameType nameType = NameType.HOST_NAME;

    // subclasses should add their specific actual name implementation
}

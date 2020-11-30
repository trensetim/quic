package com.timtrense.quic.tls;

import java.util.List;
import lombok.NonNull;

/**
 * Interface to be implemented by {@link Handshake handshake messages} that contain {@link Extension extensions}
 *
 * @author Tim Trense
 */
public interface ExtensionCarryingHandshake {

    /**
     * @return a mutable list of all carried {@link Extension extension}, never null
     */
    List<Extension> getExtensions();

    /**
     * sets the internal list of carried extensions
     *
     * @param extensions the new list of carried {@link Extension extension}
     */
    void setExtensions( @NonNull List<Extension> extensions );
}

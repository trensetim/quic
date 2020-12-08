package com.timtrense.quic.tls.impl;

import java.nio.ByteBuffer;
import lombok.NonNull;

import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionCarryingHandshake;

/**
 * Interface to parsing TLS message extensions
 *
 * @author Tim Trense
 */
public interface ExtensionParser {

    /**
     * Parses one TLS 1.3 message from the given data on the wire.
     *
     * @param handshake the containing message of the extension to parse
     * @param data      the raw data from the wire, positioned at the start of this extension
     * @param maxLength the remaining length of the buffer, that this next message could take at most
     * @return a parsed, valid message
     * @throws QuicParsingException if any parsing error occurs
     */
    Extension parseExtension(
            @NonNull ExtensionCarryingHandshake handshake,
            @NonNull ByteBuffer data,
            int maxLength )
            throws QuicParsingException;
}

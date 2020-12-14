package com.timtrense.quic.impl.base;

import lombok.Data;
import lombok.NonNull;

import com.timtrense.quic.StatelessResetToken;

/**
 * Default implementation of {@link StatelessResetToken}
 *
 * @author Tim Trense
 */
@Data
public class StatelessResetTokenImpl implements StatelessResetToken {

    private @NonNull byte[] value;

}

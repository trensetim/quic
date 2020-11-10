package com.timtrense.quic.impl.base;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import com.timtrense.quic.CreditBasedFlowControl;
import com.timtrense.quic.Stream;
import com.timtrense.quic.StreamId;
import com.timtrense.quic.StreamPriority;

/**
 * @author Tim Trense
 */
@Data
@RequiredArgsConstructor
@AllArgsConstructor
public class StreamImpl implements Stream {

    private final @NonNull StreamId id;
    private final @NonNull CreditBasedFlowControl sendingFlowControl;
    private final @NonNull CreditBasedFlowControl receivingFlowControl;
    private @NonNull StreamPriority priority = DefaultStreamPriority.BASE_PRIORITY;
    private @NonNull SendingStreamStateImpl currentSendingState = SendingStreamStateImpl.NEW;
    private @NonNull ReceivingStreamStateImpl currentReceivingState = ReceivingStreamStateImpl.NEW;

}

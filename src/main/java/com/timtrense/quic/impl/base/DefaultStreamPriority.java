package com.timtrense.quic.impl.base;

import com.timtrense.quic.StreamPriority;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

/**
 * The default implementation of {@link com.timtrense.quic.StreamPriority}
 *
 * @author Tim Trense
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DefaultStreamPriority implements StreamPriority {

    public static final DefaultStreamPriority BASE_PRIORITY = new DefaultStreamPriority( 0 );
    public static final DefaultStreamPriority MAX_PRIORITY = new DefaultStreamPriority( Integer.MAX_VALUE );
    public static final DefaultStreamPriority MIN_PRIORITY = new DefaultStreamPriority( Integer.MIN_VALUE );

    private int value = 0;

    @Override
    public int compareTo( @NonNull StreamPriority o ) {
        if ( o instanceof DefaultStreamPriority ) {
            return Integer.compare( value, ( (DefaultStreamPriority)o ).value );
        }
        else {
            return 0;
        }
    }
}

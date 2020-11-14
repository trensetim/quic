package com.timtrense.quic;

/**
 * A Stream Priority is an indicator for the RELATIVE priority compared to the other streams of a connection.
 * All streams within a connection MUST use the same (or a comparable one) implementation for their priority.
 * All streams start with the default value for their priority implementation, making all equally relevant.
 * <p>
 * Comparing instances of non-comparable implementations SHOULD result in EQUAL PRIORITY (thus
 * {@link Comparable#compareTo(Object)} returns 0.
 * <p>
 * <p/>
 * <h2>Stream Prioritization</h2>
 * Stream multiplexing can have a significant effect on application
 * performance if resources allocated to streams are correctly
 * prioritized.
 * <p>
 * QUIC does not provide a mechanism for exchanging prioritization
 * information.  Instead, it relies on receiving priority information
 * from the application.
 * <p>
 * A QUIC implementation SHOULD provide ways in which an application can
 * indicate the <b>relative priority of streams</b>.  An implementation uses
 * information provided by the application to determine how to allocate
 * resources to active streams.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-2.3">QUIC Spec/Section 2.3</a>
 */
public interface StreamPriority extends Comparable<StreamPriority> {

}

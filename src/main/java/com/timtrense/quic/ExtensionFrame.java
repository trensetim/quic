package com.timtrense.quic;

/**
 * All QUIC extensions that provide frames MUST let them implement this interface
 *
 * QUIC frames do not use a self-describing encoding.  An endpoint
 * therefore needs to understand the syntax of all frames before it can
 * successfully process a packet.  This allows for efficient encoding of
 * frames, but it means that an endpoint cannot send a frame of a type
 * that is unknown to its peer.
 *
 * An extension to QUIC that wishes to use a new type of frame MUST
 * first ensure that a peer is able to understand the frame.  An
 * endpoint can use a transport parameter to signal its willingness to
 * receive extension frame types.  One transport parameter can indicate
 * support for one or more extension frame types.
 *
 * Extensions that modify or replace core protocol functionality
 * (including frame types) will be difficult to combine with other
 * extensions that modify or replace the same functionality unless the
 * behavior of the combination is explicitly defined.  Such extensions
 * SHOULD define their interaction with previously-defined extensions
 * modifying the same protocol components.
 *
 * Extension frames MUST be congestion controlled and MUST cause an ACK
 * frame to be sent.  The exception is extension frames that replace or
 * supplement the ACK frame.  Extension frames are not included in flow
 * control unless specified in the extension.
 *
 * An IANA registry is used to manage the assignment of frame types; see
 * Section 22.3.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-19.21">QUIC Spec/Section 19.21</a>
 */
public interface ExtensionFrame extends Frame {
}

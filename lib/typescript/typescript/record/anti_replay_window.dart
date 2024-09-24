const int width = 64; // bits / entries, must be multiple of INT_SIZE
const int INT_SIZE = 32; // in Dart, bitwise operators use 32bit ints

/**
 * Provides protection against replay attacks by remembering received packets in a sliding window
 */
class AntiReplayWindow {
  // window bitmap looks as follows:
  //  v- upper end                    lower end --v
  // [111011 ... window_n]...[11111101 ... window_0]
  List<int> window = [];
  int ceiling = 0; // upper end of the window bitmap / highest received seq_num

  AntiReplayWindow() {
    reset();
  }

  /**
   * Initializes the anti replay window to its default state
   */
  void reset() {
    window = List.filled(width ~/ INT_SIZE, 0);
    ceiling = width - 1;
  }

  /**
   * Checks if the packet with the given sequence number may be received or has to be discarded
   * @param seq_num - The sequence number of the packet to be checked
   */
  bool mayReceive(int seqNum) {
    if (seqNum > ceiling + width) {
      // we skipped a lot of packets... I don't think we should accept
      return false;
    } else if (seqNum > ceiling) {
      // always accept new packets
      return true;
    } else if (seqNum >= ceiling - width + 1 && seqNum <= ceiling) {
      // packet falls within the window, check if it was received already.
      // if so, don't accept
      return !hasReceived(seqNum);
    } else {
      // too old, don't accept
      return false;
    }
  }

  /**
   * Checks if the packet with the given sequence number is marked as received
   * @param seq_num - The sequence number of the packet to be checked
   */
  bool hasReceived(int seqNum) {
    // check if the packet was received already
    final lowerBound = ceiling - width + 1;
    // find out where the bit is located
    final bitIndex = seqNum - lowerBound;
    final windowIndex = bitIndex ~/ INT_SIZE;
    final windowBit = bitIndex % INT_SIZE;
    final flag = 1 << windowBit;
    // check if it is set;
    return (window[windowIndex] & flag) == flag;
  }

  /**
   * Marks the packet with the given sequence number as received
   * @param seq_num - The sequence number of the packet
   */
  void markAsReceived(int seqNum) {
    if (seqNum > ceiling) {
      // shift the window
      var amount = seqNum - ceiling;
      // first shift whole blocks
      while (amount > INT_SIZE) {
        for (var i = 1; i < window.length; i++) {
          window[i - 1] = window[i];
        }
        window[window.length - 1] = 0;
        amount -= INT_SIZE;
      }
      // now shift bitwise (to the right)
      var overflow = 0;
      for (var i = 0; i < window.length; i++) {
        overflow = window[i] << (INT_SIZE - amount); // BBBBBBAA => AA000000
        window[i] = window[i] >>> amount; // BBBBBBAA ==> 00BBBBBB
        if (i > 0) window[i - 1] |= overflow;
      }
      // and remember the new ceiling
      ceiling = seqNum;
    }
    final lowerBound = ceiling - width + 1;

    // find out where the bit is located
    final bitIndex = seqNum - lowerBound;
    final windowIndex = bitIndex ~/ INT_SIZE;
    final windowBit = bitIndex % INT_SIZE;
    final flag = 1 << windowBit;
    // and set it
    window[windowIndex] |= flag;
  }
}
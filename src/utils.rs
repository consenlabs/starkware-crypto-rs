/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
pub fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
  if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
    return Err(());
  }

  let mut b = 0;
  let mut idx = 0;
  for c in hex.bytes() {
    b <<= 4;
    match c {
      b'A'..=b'F' => b |= c - b'A' + 10,
      b'a'..=b'f' => b |= c - b'a' + 10,
      b'0'..=b'9' => b |= c - b'0',
      _ => return Err(()),
    }
    if (idx & 1) == 1 {
      target[idx / 2] = b;
      b = 0;
    }
    idx += 1;
  }
  Ok(idx / 2)
}
/// Simple partial preimage calculation. OG Hashcash.
pub fn work(hash_bytes: &[u8]) -> u64 {
    let mut total_leading_zero_bits = 0;
    for byte in hash_bytes {
        let byte_leading_zero_bits = byte.leading_zeros();
        total_leading_zero_bits += byte_leading_zero_bits;

        if byte_leading_zero_bits != 8 {
            break;
        }
    }
    let base: u64 = 2;
    base.pow(total_leading_zero_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn work_calculation() {
        let bytes: Vec<u8> = vec![0, 0, 255, 0];
        assert_eq!(work(&bytes), 65536);
    }
}

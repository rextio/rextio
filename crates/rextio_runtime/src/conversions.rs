use crate::errors::RextioRuntimeError;

pub fn len_to_i64(len: usize) -> Result<i64, RextioRuntimeError> {
    i64::try_from(len).map_err(|_| RextioRuntimeError::new("sequence length does not fit in i64"))
}

pub fn checked_index(index: i64, len: usize) -> Result<usize, RextioRuntimeError> {
    if index < 0 {
        return Err(RextioRuntimeError::new(
            "negative indexes are not supported",
        ));
    }

    let index = usize::try_from(index)
        .map_err(|_| RextioRuntimeError::new("index does not fit in usize"))?;
    if index >= len {
        return Err(RextioRuntimeError::new("index out of bounds"));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::{checked_index, len_to_i64};

    #[test]
    fn converts_sequence_length() {
        assert_eq!(len_to_i64(3), Ok(3));
    }

    #[test]
    fn checks_index_bounds() {
        assert_eq!(checked_index(1, 3), Ok(1));
        assert_eq!(
            checked_index(-1, 3).unwrap_err().message(),
            "negative indexes are not supported"
        );
        assert_eq!(
            checked_index(3, 3).unwrap_err().message(),
            "index out of bounds"
        );
    }
}

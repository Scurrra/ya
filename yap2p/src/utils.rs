use std::collections::VecDeque;

use generic_array::{typenum::U16, GenericArray};

/// Split data into chunks for encryption/decryption
/// 
/// Arguments
/// 
/// * `data` --- data to be splitted into chunks length 16 
pub(crate) fn chunk_data_for_encryption(data: impl AsRef<[u8]>) -> Vec<GenericArray<u8, U16>> {
    let length = data.as_ref().len();

    // check if we can split data into equal pieces length 16
    if length % 16 == 0 {
        return data.as_ref()
            .chunks(16)
            .map(|c| GenericArray::clone_from_slice(c))
            .collect::<Vec<GenericArray<u8, U16>>>()
    } else { 
        // if we can not split data into equal pieces, we have to add zeroes in the end
        // the way to have less copies is to split all data without remainder (data.len() % 16)
        let mut buf = data.as_ref()[..(16*(length/16))]
            .chunks(16)
            .map(|c| GenericArray::clone_from_slice(c))
            .collect::<Vec<GenericArray<u8, U16>>>();
        
        // and than manually copy the remainder into [0u8; 16] to "cheaply" add zeroes at the end
        let mut last = GenericArray::from([0u8; 16]);
        {
            let (left, right) = last.split_at_mut(length%16);
            left.copy_from_slice(&data.as_ref()[(length-length%16)..]);
            last[15] = right.len() as u8;
        }
        buf.push(last);

        return buf;
    }
}

/// Split data into chunks for packets
/// 
/// Arguments
/// 
/// * `data` --- data to be splitted into chunks
/// * `piece_len` --- maximum length of pieces
pub(crate) fn chunk_data_for_packet_split(data: impl AsRef<[u8]>, piece_len: usize) -> VecDeque<Vec<u8>> {
    let length = data.as_ref().len();

    // check if we can split data into equal pieces length 16
    if length % piece_len == 0 {
        return data.as_ref()
            .chunks(piece_len)
            .map(|c| Vec::from(c))
            .collect::<VecDeque<Vec<u8>>>()
    } else { 
        // if we can not split data into equal pieces, we have to add zeroes in the end
        // the way to have less copies is to split all data without remainder (data.len() % 1120)
        let mut buf = data.as_ref()[..(piece_len*(length/piece_len))]
            .chunks(piece_len)
            .map(|c| Vec::from(c))
            .collect::<VecDeque<Vec<u8>>>();
        // and finally add remainder
        buf.push_back(data.as_ref()[(length-length%piece_len)..].to_vec());

        return buf;
    }
}
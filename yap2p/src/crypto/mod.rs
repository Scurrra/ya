//! YAP2P crypto primitives
//! 
//! Module contains structures for [Diffie-Hellman](dh::DH) public
//! key exchange, encription keys' storing, and messages' storing.

use generic_array::{typenum::U16, GenericArray};

pub mod dh;
pub mod keychain;
pub mod history;

/// Split data into chunks for encryption/decryption
/// 
/// Arguments
/// 
/// * `data` --- data to be splitted into chunks length 16 
pub(crate) fn chunk_data(data: impl AsRef<[u8]>) -> Vec<GenericArray<u8, U16>> {
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
            let (left, _) = last.split_at_mut(length%16);
            left.copy_from_slice(&data.as_ref()[(length-length%16)..])
        }
        buf.push(last);

        return buf;
    }
}
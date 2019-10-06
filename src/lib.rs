use std::convert::From;

use octetkeypair::{PublicBytes, PrivateBytes, Curve25519PubKey, Curve25519PrvKey};
use sodiumoxide::crypto::sign::ed25519::{PublicKey,SecretKey};

pub struct OkpPubKey(pub Curve25519PubKey);
pub struct OkpPrvKey(pub Curve25519PrvKey);



#[macro_export]
macro_rules! pub_key {
    ($e:expr) => (PublicKey::from(OkpPubKey($e)));
}

#[macro_export]
macro_rules! pub_key_from_json_str {
    ($e:expr) => (serde_json::from_str::<Curve25519PubKey>($e).map(|k| PublicKey::from(OkpPubKey(k))));
}

#[macro_export]
macro_rules! prv_key {
    ($e:expr) => (SecretKey::from(OkpPrvKey($e)));
}

#[macro_export]
macro_rules! prv_key_from_json_str {
    ($e:expr) => (serde_json::from_str::<Curve25519PrvKey>($e).map(|k| SecretKey::from(OkpPrvKey(k))));
}


impl From<OkpPrvKey> for Curve25519PrvKey {
    fn from(prv_key:OkpPrvKey) -> Self {
        prv_key.0
    }
}


impl From<Curve25519PrvKey> for OkpPrvKey {
    fn from(prv_key:Curve25519PrvKey) -> Self {
        OkpPrvKey(prv_key)
    }
}

impl From<SecretKey> for OkpPrvKey {
    fn from(prv_key:SecretKey) -> Self {
        let mut private = PrivateBytes([0;32]);
        for (li, ri) in private.0.iter_mut().zip(prv_key.0[..32].iter()) {
            *li = *ri;
        }

        let mut public  = PublicBytes([0;32]);
        for (li, ri) in public.0.iter_mut().zip(prv_key.0[32..].iter()) {
            *li = *ri;
        }

        OkpPrvKey(Curve25519PrvKey{
            private,
            public,
        })
    }
}

impl From<OkpPrvKey> for SecretKey {
    fn from(prv_key:OkpPrvKey) -> Self {
        let s = prv_key.0.private.0;
        let p = prv_key.0.public.0;

        let b = [
            s[ 0], s[ 1], s[ 2], s[ 3], s[ 4], s[ 5], s[ 6], s[ 7],
            s[ 8], s[ 9], s[10], s[11], s[12], s[13], s[14], s[15],
            s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
            s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],
            p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15],
            p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
            p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31],
        ];

        SecretKey(b)
    }
}


impl From<Curve25519PubKey> for OkpPubKey {
    fn from(pub_key:Curve25519PubKey) -> Self {
        OkpPubKey(pub_key)
    }
}

impl From<OkpPubKey> for Curve25519PubKey {
    fn from(pub_key:OkpPubKey) -> Self {
        pub_key.0
    }
}

impl From<PublicKey> for OkpPubKey {
    fn from(pub_key:PublicKey) -> Self {
        OkpPubKey(Curve25519PubKey{ public: PublicBytes(pub_key.0) })
    }
}

impl From<OkpPubKey> for PublicKey {
    fn from(pub_key:OkpPubKey) -> Self {
        PublicKey(pub_key.0.public.0)
    }
}

#[cfg(test)]
mod tests {
    use octetkeypair::{Curve25519PubKey, Curve25519PrvKey};
    use sodiumoxide::crypto::sign::ed25519::{PublicKey,SecretKey};
    use crate::*;
    use serde_json::Value;
    use json_digest;

    const PRV_KEY_EXAMPLE: &'static str = r###"
{
    "kty":"OKP",
    "crv":"Ed25519",
    "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

}
"###;
    const PUB_KEY_EXAMPLE: &'static str = r###"
{
    "kty":"OKP",
    "crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
"###;


    const ED25519_PRV_KEY_EXAMPLE: [u8;64] =  [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    const ED25519_PUB_KEY_EXAMPLE: [u8;32] =  [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];


    #[test]
    fn convert_to_sodiumoxide_works() {
        let prv_res = prv_key_from_json_str!(PRV_KEY_EXAMPLE);

        assert!(prv_res.is_ok());

        let sk = prv_res.unwrap();

        for (l,r) in sk.0.iter().zip(ED25519_PRV_KEY_EXAMPLE.iter()) {
            assert_eq!(l,r);
        }

        let pub_res = pub_key_from_json_str!(PUB_KEY_EXAMPLE);

        assert!(pub_res.is_ok());

        let pk = pub_res.unwrap();

        for (l,r) in pk.0.iter().zip(ED25519_PUB_KEY_EXAMPLE.iter()) {
            assert_eq!(l,r);
        }
    }

    #[test]
    fn convert_from_sodiumoxide_works() {
        let prv_res = prv_key_from_json_str!(PRV_KEY_EXAMPLE);
        assert!(prv_res.is_ok());
        let prv = prv_res.unwrap();
        let prv2:OkpPrvKey = prv.into();
        let prv3:Curve25519PrvKey = prv2.into();
        let parsed_and_converted_json_val_res = serde_json::to_value(prv3);

        assert!(parsed_and_converted_json_val_res.is_ok());

        let parsed_and_converted_json_val = parsed_and_converted_json_val_res.unwrap();

        let expected_json_val_res =
            serde_json::from_str::<Value>(PRV_KEY_EXAMPLE);

        assert!(expected_json_val_res.is_ok());

        let expected_json_val = expected_json_val_res.unwrap();

        let mut parsed = [0u8;32];
        json_digest::sha256::json_digest(&mut parsed, &parsed_and_converted_json_val);

        let mut expected = [0u8;32];
        json_digest::sha256::json_digest(&mut expected, &expected_json_val);

        assert_eq!(parsed, expected);
    }
}

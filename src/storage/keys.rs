use cosmwasm_std::Addr;

use crate::storage::de::KeyDeserialize;
use crate::storage::helpers::namespaces_with_key;
use crate::storage::int_key::CwIntKey;

#[derive(Debug)]
pub enum Key<'a> {
    Ref(&'a [u8]),
    Val8([u8; 1]),
    Val16([u8; 2]),
    Val32([u8; 4]),
    Val64([u8; 8]),
    Val128([u8; 16]),
}

impl<'a> AsRef<[u8]> for Key<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Key::Ref(r) => r,
            Key::Val8(v) => v,
            Key::Val16(v) => v,
            Key::Val32(v) => v,
            Key::Val64(v) => v,
            Key::Val128(v) => v,
        }
    }
}

impl<'a> PartialEq<&[u8]> for Key<'a> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_ref() == *other
    }
}

/// `PrimaryKey` needs to be implemented for types that want to be a `Map` (or `Map`-like) key,
/// or part of a key.
///
/// In particular, it defines a series of types that help iterating over parts of a (composite) key:
///
/// `Prefix`: Prefix is eager. That is, except for empty keys, it's always "one less" than the full key.
/// `Suffix`: Suffix is the complement of prefix.
/// `SubPrefix`: Sub-prefix is "one less" than prefix.
/// `SuperSuffix`: Super-suffix is "one more" than suffix. The complement of sub-prefix.
///
/// By example, for a 2-tuple `(T, U)`:
///
/// `T`: Prefix.
/// `U`: Suffix.
/// `()`: Sub-prefix.
/// `(T, U)`: Super-suffix.
///
/// `SubPrefix` and `SuperSuffix` only make real sense in the case of triples. Still, they need to be
/// consistently defined for all types.
pub trait PrimaryKey<'a>: Clone {
    /// These associated types need to implement `Prefixer`, so that they can be useful arguments
    /// for `prefix()`, `sub_prefix()`, and their key-deserializable variants.
    type Prefix: Prefixer<'a>;
    type SubPrefix: Prefixer<'a>;

    /// These associated types need to implement `KeyDeserialize`, so that they can be returned from
    /// `range_de()` and friends.
    type Suffix: KeyDeserialize;
    type SuperSuffix: KeyDeserialize;

    /// returns a slice of key steps, which can be optionally combined
    fn key(&self) -> Vec<Key>;

    fn joined_key(&self) -> Vec<u8> {
        let keys = self.key();
        let l = keys.len();
        namespaces_with_key(
            &keys[0..l - 1].iter().map(Key::as_ref).collect::<Vec<_>>(),
            keys[l - 1].as_ref(),
        )
    }

    fn joined_extra_key(&self, key: &[u8]) -> Vec<u8> {
        let keys = self.key();
        namespaces_with_key(&keys.iter().map(Key::as_ref).collect::<Vec<_>>(), key)
    }
}

// Empty / no primary key
impl<'a> PrimaryKey<'a> for () {
    type Prefix = Self;
    type SubPrefix = Self;
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![]
    }
}

impl<'a> PrimaryKey<'a> for &'a [u8] {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(self)]
    }
}

// Provide a string version of this to raw encode strings
impl<'a> PrimaryKey<'a> for &'a str {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(self.as_bytes())]
    }
}

// use generics for combining there - so we can use &[u8], Vec<u8>, or IntKey
impl<'a, T: PrimaryKey<'a> + Prefixer<'a> + KeyDeserialize, U: PrimaryKey<'a> + KeyDeserialize>
    PrimaryKey<'a> for (T, U)
{
    type Prefix = T;
    type SubPrefix = ();
    type Suffix = U;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        let mut keys = self.0.key();
        keys.extend(self.1.key());
        keys
    }
}

// use generics for combining there - so we can use &[u8], Vec<u8>, or IntKey
impl<
        'a,
        T: PrimaryKey<'a> + Prefixer<'a>,
        U: PrimaryKey<'a> + Prefixer<'a> + KeyDeserialize,
        V: PrimaryKey<'a> + KeyDeserialize,
    > PrimaryKey<'a> for (T, U, V)
{
    type Prefix = (T, U);
    type SubPrefix = T;
    type Suffix = V;
    type SuperSuffix = (U, V);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.0.key();
        keys.extend(self.1.key());
        keys.extend(self.2.key());
        keys
    }
}

pub trait Prefixer<'a> {
    /// returns 0 or more namespaces that should be length-prefixed and concatenated for range searches
    fn prefix(&self) -> Vec<Key>;

    fn joined_prefix(&self) -> Vec<u8> {
        let prefixes = self.prefix();
        namespaces_with_key(&prefixes.iter().map(Key::as_ref).collect::<Vec<_>>(), &[])
    }
}

impl<'a> Prefixer<'a> for () {
    fn prefix(&self) -> Vec<Key> {
        vec![]
    }
}

impl<'a> Prefixer<'a> for &'a [u8] {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self)]
    }
}

impl<'a, T: Prefixer<'a>, U: Prefixer<'a>> Prefixer<'a> for (T, U) {
    fn prefix(&self) -> Vec<Key> {
        let mut res = self.0.prefix();
        res.extend(self.1.prefix().into_iter());
        res
    }
}

impl<'a, T: Prefixer<'a>, U: Prefixer<'a>, V: Prefixer<'a>> Prefixer<'a> for (T, U, V) {
    fn prefix(&self) -> Vec<Key> {
        let mut res = self.0.prefix();
        res.extend(self.1.prefix().into_iter());
        res.extend(self.2.prefix().into_iter());
        res
    }
}

// Provide a string version of this to raw encode strings
impl<'a> Prefixer<'a> for &'a str {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_bytes())]
    }
}

impl<'a> PrimaryKey<'a> for Vec<u8> {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self)]
    }
}

impl<'a> Prefixer<'a> for Vec<u8> {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_ref())]
    }
}

impl<'a> PrimaryKey<'a> for String {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for String {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_bytes())]
    }
}

/// type safe version to ensure address was validated before use.
impl<'a> PrimaryKey<'a> for &'a Addr {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(self.as_ref().as_bytes())]
    }
}

impl<'a> Prefixer<'a> for &'a Addr {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_bytes())]
    }
}

/// owned variant.
impl<'a> PrimaryKey<'a> for Addr {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(self.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for Addr {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.as_bytes())]
    }
}

macro_rules! integer_key {
    (for $($t:ty, $v:tt),+) => {
        $(impl<'a> PrimaryKey<'a> for $t {
            type Prefix = ();
            type SubPrefix = ();
            type Suffix = Self;
            type SuperSuffix = Self;

            fn key(&self) -> Vec<Key> {
                vec![Key::$v(self.to_cw_bytes())]
            }
        })*
    }
}

integer_key!(for i8, Val8, u8, Val8, i16, Val16, u16, Val16, i32, Val32, u32, Val32, i64, Val64, u64, Val64, i128, Val128, u128, Val128);

macro_rules! integer_prefix {
    (for $($t:ty, $v:tt),+) => {
        $(impl<'a> Prefixer<'a> for $t {
            fn prefix(&self) -> Vec<Key> {
                vec![Key::$v(self.to_cw_bytes())]
            }
        })*
    }
}

integer_prefix!(for i8, Val8, u8, Val8, i16, Val16, u16, Val16, i32, Val32, u32, Val32, i64, Val64, u64, Val64, i128, Val128, u128, Val128);

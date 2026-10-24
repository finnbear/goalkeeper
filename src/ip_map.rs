//! A map keyed by address, smaller than one keyed by [`IpAddr`].
//!
//! An `IpAddr` is 17 bytes, a tag and room for the longer family, which a
//! hash map pads out to its value's alignment: a `u32` beside one takes 24
//! bytes where beside an [`Ipv4Addr`] it takes 8. Keeping each family in a map
//! of its own stores IPv4 keys in 4 bytes and IPv6 keys in 16.
//!
//! Only what this crate uses of [`std::collections::HashMap`]'s API, entries
//! included, so a caller reads as it would against one.

use fxhash::FxHashMap;
use std::collections::hash_map;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// See the module docs.
#[derive(Debug)]
pub(crate) struct IpMap<V> {
    v4: FxHashMap<Ipv4Addr, V>,
    v6: FxHashMap<Ipv6Addr, V>,
}

impl<V> Default for IpMap<V> {
    fn default() -> Self {
        Self {
            v4: FxHashMap::default(),
            v6: FxHashMap::default(),
        }
    }
}

impl<V> IpMap<V> {
    pub(crate) fn get(&self, ip: &IpAddr) -> Option<&V> {
        match ip {
            IpAddr::V4(ip) => self.v4.get(ip),
            IpAddr::V6(ip) => self.v6.get(ip),
        }
    }

    pub(crate) fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut V> {
        match ip {
            IpAddr::V4(ip) => self.v4.get_mut(ip),
            IpAddr::V6(ip) => self.v6.get_mut(ip),
        }
    }

    pub(crate) fn entry(&mut self, ip: IpAddr) -> Entry<'_, V> {
        match ip {
            IpAddr::V4(ip) => match self.v4.entry(ip) {
                hash_map::Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry::V4(entry)),
                hash_map::Entry::Vacant(entry) => Entry::Vacant(VacantEntry::V4(entry)),
            },
            IpAddr::V6(ip) => match self.v6.entry(ip) {
                hash_map::Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry::V6(entry)),
                hash_map::Entry::Vacant(entry) => Entry::Vacant(VacantEntry::V6(entry)),
            },
        }
    }

    pub(crate) fn retain(&mut self, mut f: impl FnMut(IpAddr, &mut V) -> bool) {
        self.v4.retain(|ip, v| f(IpAddr::V4(*ip), v));
        self.v6.retain(|ip, v| f(IpAddr::V6(*ip), v));
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (IpAddr, &V)> + '_ {
        let v4 = self.v4.iter().map(|(ip, v)| (IpAddr::V4(*ip), v));
        let v6 = self.v6.iter().map(|(ip, v)| (IpAddr::V6(*ip), v));
        v4.chain(v6)
    }

    #[allow(dead_code, reason = "the rest of a map's API")]
    pub(crate) fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    #[allow(dead_code, reason = "the rest of a map's API")]
    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// See [`hash_map::Entry`].
pub(crate) enum Entry<'a, V> {
    Occupied(OccupiedEntry<'a, V>),
    Vacant(VacantEntry<'a, V>),
}

impl<'a, V> Entry<'a, V> {
    pub(crate) fn or_insert_with(self, f: impl FnOnce() -> V) -> &'a mut V {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert(f()),
        }
    }
}

/// See [`hash_map::OccupiedEntry`].
pub(crate) enum OccupiedEntry<'a, V> {
    V4(hash_map::OccupiedEntry<'a, Ipv4Addr, V>),
    V6(hash_map::OccupiedEntry<'a, Ipv6Addr, V>),
}

impl<'a, V> OccupiedEntry<'a, V> {
    pub(crate) fn get(&self) -> &V {
        match self {
            Self::V4(entry) => entry.get(),
            Self::V6(entry) => entry.get(),
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut V {
        match self {
            Self::V4(entry) => entry.get_mut(),
            Self::V6(entry) => entry.get_mut(),
        }
    }

    pub(crate) fn into_mut(self) -> &'a mut V {
        match self {
            Self::V4(entry) => entry.into_mut(),
            Self::V6(entry) => entry.into_mut(),
        }
    }

    pub(crate) fn remove(self) -> V {
        match self {
            Self::V4(entry) => entry.remove(),
            Self::V6(entry) => entry.remove(),
        }
    }
}

/// See [`hash_map::VacantEntry`].
pub(crate) enum VacantEntry<'a, V> {
    V4(hash_map::VacantEntry<'a, Ipv4Addr, V>),
    V6(hash_map::VacantEntry<'a, Ipv6Addr, V>),
}

impl<'a, V> VacantEntry<'a, V> {
    pub(crate) fn insert(self, value: V) -> &'a mut V {
        match self {
            Self::V4(entry) => entry.insert(value),
            Self::V6(entry) => entry.insert(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_family_is_kept_apart_and_read_back_as_given() {
        let mut map = IpMap::default();
        let v4 = IpAddr::from([0, 0, 0, 1]);
        // The same bits, as IPv6: a different key.
        let v6 = IpAddr::from(Ipv6Addr::from_bits(1));
        *map.entry(v4).or_insert_with(|| 0) += 1;
        *map.entry(v6).or_insert_with(|| 0) += 10;
        *map.entry(v4).or_insert_with(|| 0) += 1;
        assert_eq!((map.get(&v4), map.get(&v6)), (Some(&2), Some(&10)));
        assert_eq!(map.len(), 2);
        let mut all: Vec<_> = map.iter().map(|(ip, v)| (ip, *v)).collect();
        all.sort();
        assert_eq!(all, [(v4, 2), (v6, 10)]);

        match map.entry(v6) {
            Entry::Occupied(entry) => assert_eq!(entry.remove(), 10),
            Entry::Vacant(_) => panic!("inserted above"),
        }
        map.retain(|ip, _| ip != v4);
        assert!(map.is_empty());
    }
}

use orga::{collections::Map, orga, Result};

/// A Bitcoin transaction ID and output index.
pub type Outpoint = ([u8; 32], u32);

/// A collection to keep track of which deposit outpoints have already been
/// relayed, in order to ensure that we don't credit the same deposit more than
/// once.
///
/// Outpoints are stored in a set, and added to a queue with an expiration
/// timestamp so we can prune the set.
///
/// It is important for safety that outpoints can not expire from the set until
/// after they are no longer considered valid to relay, otherwise there is risk
/// of the network crediting a deposit twice. Care should be taken to configure
/// usage of this collection to set timestamps properly to ensure this does not
/// happen.
#[orga]
pub struct OutpointSet {
    /// A queue of outpoints to expire, sorted by expiration timestamp.
    pub(super) expiration_queue: Map<(u64, Outpoint), ()>,

    /// A set of outpoints.
    pub(super) outpoints: Map<Outpoint, ()>,
}

#[orga]
impl OutpointSet {
    /// Clear the set.
    pub fn reset(&mut self) -> Result<()> {
        super::clear_map(&mut self.expiration_queue)?;
        super::clear_map(&mut self.outpoints)?;

        Ok(())
    }

    /// Check if the set contains an outpoint.
    #[query]
    pub fn contains(&self, outpoint: Outpoint) -> Result<bool> {
        self.outpoints.contains_key(outpoint)
    }

    /// Insert an outpoint into the set, to be pruned at the given expiration
    /// timestamp.
    pub fn insert(&mut self, outpoint: Outpoint, expiration: u64) -> Result<()> {
        self.outpoints.insert(outpoint, ())?;
        self.expiration_queue.insert((expiration, outpoint), ())?;
        Ok(())
    }

    /// Remove expired outpoints from the set.
    pub fn remove_expired(&mut self, now: u64) -> Result<()> {
        // TODO: use drain iterator to eliminate need to collect into vec
        let mut expired = vec![];
        for entry in self.expiration_queue.iter()? {
            let (entry, _) = entry?;
            let (expiration, outpoint) = *entry;
            if expiration >= now {
                break;
            }
            expired.push((expiration, outpoint));
        }

        for (expiration, outpoint) in expired {
            self.outpoints.remove(outpoint)?;
            self.expiration_queue.remove((expiration, outpoint))?;
        }

        Ok(())
    }
}

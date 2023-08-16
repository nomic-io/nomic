use orga::{collections::Map, orga, Result};

pub type Outpoint = ([u8; 32], u32);

#[orga]
pub struct OutpointSet {
    pub(super) expiration_queue: Map<(u64, Outpoint), ()>,
    pub(super) outpoints: Map<Outpoint, ()>,
}

#[orga]
impl OutpointSet {
    pub fn reset(&mut self) -> Result<()> {
        super::clear_map(&mut self.expiration_queue)?;
        super::clear_map(&mut self.outpoints)?;

        Ok(())
    }

    #[query]
    pub fn contains(&self, outpoint: Outpoint) -> Result<bool> {
        self.outpoints.contains_key(outpoint)
    }

    pub fn insert(&mut self, outpoint: Outpoint, expiration: u64) -> Result<()> {
        self.outpoints.insert(outpoint, ())?;
        self.expiration_queue.insert((expiration, outpoint), ())?;
        Ok(())
    }

    pub fn remove_expired(&mut self, now: u64) -> Result<()> {
        // TODO: use drain iterator to eliminate need to collect into vec
        let mut expired = vec![];
        for entry in self.expiration_queue.iter()? {
            let (entry, _) = entry?;
            let (expiration, outpoint) = *entry;
            if expiration > now {
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

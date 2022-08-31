use nomicv3::bitcoin::SignatoryKeys as SignatoryKeysV3;
use orga::migrate::Migrate;

use nomicv3::bitcoin::checkpoint::CheckpointQueue as CheckpointQueueV3;
use nomicv3::bitcoin::header_queue::HeaderQueue as HeaderQueueV3;
use nomicv3::orga::encoding::Encode as EncodeV3;
use orga::encoding::Decode;

use super::checkpoint::CheckpointQueue;
use super::header_queue::HeaderQueue;
use super::txid_set::OutpointSet;
use super::SignatoryKeys;

fn migrate_encoding<T: EncodeV3, U: Decode>(value: &T) -> orga::Result<U> {
    Ok(Decode::decode(value.encode().unwrap().as_slice())?)
}

impl Migrate<HeaderQueueV3> for HeaderQueue {
    fn migrate(&mut self, legacy: HeaderQueueV3) -> orga::Result<()> {
        let (deque, current_work) = legacy.explode();

        self.deque.migrate(deque)?;
        self.current_work = migrate_encoding(&current_work)?;

        Ok(())
    }
}

use nomicv3::bitcoin::txid_set::OutpointSet as OutpointSetV3;
impl Migrate<OutpointSetV3> for OutpointSet {
    fn migrate(&mut self, legacy: OutpointSetV3) -> orga::Result<()> {
        let (expiration_queue, outpoints) = legacy.explode();

        self.expiration_queue.migrate(expiration_queue)?;
        self.outpoints.migrate(outpoints)?;

        Ok(())
    }
}

impl Migrate<CheckpointQueueV3> for CheckpointQueue {
    fn migrate(&mut self, legacy: CheckpointQueueV3) -> orga::Result<()> {
        let (queue, index) = legacy.explode();
        self.queue.migrate(queue)?;
        self.index = index;

        Ok(())
    }
}

impl Migrate<SignatoryKeysV3> for SignatoryKeys {
    fn migrate(&mut self, legacy: SignatoryKeysV3) -> orga::Result<()> {
        let (by_cons, xpubs) = legacy.explode();
        self.by_cons.migrate(by_cons)?;
        self.xpubs.migrate(xpubs)?;

        Ok(())
    }
}

impl Migrate<nomicv3::bitcoin::Bitcoin> for super::Bitcoin {
    fn migrate(&mut self, legacy: nomicv3::bitcoin::Bitcoin) -> orga::Result<()> {
        self.reward_pool.migrate(legacy.reward_pool())?;
        self.headers.migrate(legacy.headers)?;
        self.accounts.migrate(legacy.accounts)?;
        self.processed_outpoints
            .migrate(legacy.processed_outpoints)?;
        self.checkpoints.migrate(legacy.checkpoints)?;
        self.signatory_keys.migrate(legacy.signatory_keys)?;

        Ok(())
    }
}

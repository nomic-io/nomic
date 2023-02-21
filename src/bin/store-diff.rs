use orga::merk::merk::Result;
use orga::merk::MerkStore;
use orga::store::Read;
use std::path::PathBuf;

fn _store_diff(path_a: PathBuf, path_b: PathBuf) -> Result<()> {
    let mut iter_a = MerkStore::new(path_a.clone()).into_iter(..);
    let mut iter_b = MerkStore::new(path_b.clone()).into_iter(..);

    loop {
        let entry_a = iter_a.next();
        let entry_b = iter_b.next();

        let done = match (entry_a, entry_b) {
            (None, None) => {
                println!("stores are identical");
                true
            }
            (None, Some(_)) => {
                println!("store b has more entries");
                true
            }
            (Some(_), None) => {
                println!("store a has more entries");
                true
            }
            (Some(Ok((key_a, value_a))), Some(Ok((key_b, value_b)))) => {
                let mut done = false;

                if key_a != key_b {
                    println!("keys differ. a: {:?},\n\n b: {:?}\n\n", key_a, key_b);
                    done = true;
                }
                if value_a != value_b {
                    println!(
                        "values differ. key {:?}\n\n a: {:?},\n\n b: {:?}\n\n\n",
                        key_a, value_a, value_b
                    );

                    done = true;
                }

                done
            }
            other => panic!("unexpected: {:?}", other),
        };
        if done {
            break;
        }
    }
    drop(iter_a);
    drop(iter_b);

    let store_a = MerkStore::new(path_a);
    let mut iter_a = store_a.merk().raw_iter();
    let store_b = MerkStore::new(path_b);
    let mut iter_b = store_b.merk().raw_iter();

    iter_a.seek_to_first();
    iter_b.seek_to_first();
    let mut n_entries = 0;
    loop {
        match (iter_a.valid(), iter_b.valid()) {
            (true, true) => {
                n_entries += 1;
                let key_a = iter_a.key().unwrap();
                let key_b = iter_a.key().unwrap();
                if key_a != key_b {
                    panic!("keys differ. a: {:?}, b: {:?}", key_a, key_b)
                }
                let value_a = iter_a.value().unwrap();
                let value_b = iter_b.value().unwrap();
                if value_a != value_b {
                    println!("values differ. a: {:?}, b: {:?}", value_a, value_b);
                }
            }
            (true, false) => {
                let key_a = iter_a.key().unwrap();
                println!("store b is missing key: {:?}", key_a);
                iter_a.next();
            }
            (false, true) => {
                let key_b = iter_b.key().unwrap();
                println!("store a is missing key: {:?}", key_b);
                iter_b.next();
            }
            (false, false) => break,
        };
        iter_a.next();
        iter_b.next();
    }
    dbg!(n_entries);

    Ok(())
}

fn main() {}

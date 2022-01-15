use super::imports::*;
use std::fmt::Debug;
use hyxe_crypt::prelude::algorithm_dictionary::{KemAlgorithm, EncryptionAlgorithm};

#[allow(unused_results)]
pub fn handle() -> Result<Option<KernelResponse>, ConsoleError> {
    let kems = KemAlgorithm::list();
    let enxs = EncryptionAlgorithm::list();

    let mut kems_table = Table::new();
    kems_table.set_titles(prettytable::row![Fgcb => "ID", "Post-Quantum Key Encapsulation Mechanism"]);
    add_all_to_table(&mut kems_table, kems);

    let mut enxs_table = Table::new();
    enxs_table.set_titles(prettytable::row![Fgcb => "ID", "Encryption Algorithm"]);
    add_all_to_table(&mut enxs_table, enxs);

    printfs!({
        kems_table.printstd();
        enxs_table.printstd();
    });

    Ok(None)
}

fn add_all_to_table<T: Debug + Into<u8> + Copy>(table: &mut Table, input: Vec<T>) {
    input.into_iter()
        .for_each(|r|{
            let value = format!("{:?}", r);
            table.add_row(prettytable::row![c => r.into(), value]);
        })
}
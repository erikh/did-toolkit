use did_toolkit::prelude::*;

fn main() -> Result<(), anyhow::Error> {
    let mut args = std::env::args();
    let path = args.nth(1).unwrap();

    let dir = std::fs::read_dir(std::path::PathBuf::from(path))?;
    let mut reg = Registry::default();

    for item in dir {
        let item = item?;
        println!("Loading: {}", item.path().display());
        reg.load_document_cbor(item.path())?;
    }

    Ok(())
}

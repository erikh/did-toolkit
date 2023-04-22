#![allow(dead_code)]

// use std::path::PathBuf;
// use util::create_files;
//
// #[test]
// fn test_generate() {
//     let dir = PathBuf::from("/tmp/test");
//     std::fs::create_dir_all(dir.clone()).unwrap();
//     create_files(10, PathBuf::from(dir), 5).unwrap();
// }

mod util {
    use std::{collections::BTreeSet, path::PathBuf};

    use did_toolkit::{did::DID, document::Document, registry::Registry};
    use either::Either;
    use rand::Fill;
    use serde_json::json;
    //use tempfile::tempdir;

    pub fn create_files(
        count: usize,
        dir: PathBuf,
        complexity: usize,
    ) -> Result<(), anyhow::Error> {
        let mut reg: Registry = Default::default();

        for _ in 0..count {
            let doc = create_random_document(None)?;
            if let Err(e) = reg.insert(doc.clone()) {
                eprintln!("Could not generate document {}; skipping: {}", doc.id, e);
            }
        }

        link_documents_aka(&mut reg, complexity);
        link_documents_controller(&mut reg, complexity);

        let mut num = 0;

        for (_, doc) in reg.iter() {
            let filename = dir.join(&format!("{}.json", num));
            std::fs::write(filename, &json!(doc).to_string())?;
            num += 1;
        }

        Ok(())
    }

    pub fn link_documents_controller(reg: &mut Registry, iterations: usize) {
        for _ in 0..iterations {
            let one = &mut reg[rand::random::<usize>() % reg.len()].clone();
            let two = reg[rand::random::<usize>() % reg.len()].clone();

            if let None = one.controller {
                reg[&one.id].controller = Some(Either::Left(two.id));
            } else {
                match one.controller.clone().unwrap() {
                    Either::Left(did) => {
                        if did != two.id {
                            let mut set = BTreeSet::new();
                            set.insert(did);
                            set.insert(two.id);
                            reg[&one.id].controller = Some(Either::Right(set));
                        }
                    }
                    Either::Right(mut set) => {
                        set.insert(two.id);
                        reg[&one.id].controller = Some(Either::Right(set));
                    }
                }
            }
        }
    }

    pub fn link_documents_aka(reg: &mut Registry, iterations: usize) {
        for _ in 0..iterations {
            let one = reg[rand::random::<usize>() % reg.len()].clone();
            let two = reg[rand::random::<usize>() % reg.len()].clone();

            let one_id = one.id.clone();
            let two_id = two.id.clone();

            if one == two {
                continue;
            }

            if let None = one.also_known_as {
                let one = &mut reg[&one_id];
                one.also_known_as = Some(BTreeSet::new());
            }

            if let None = two.also_known_as {
                let two = &mut reg[&two_id];
                two.also_known_as = Some(BTreeSet::new());
            }

            let aka = &mut reg[&one_id].also_known_as.clone().unwrap();
            aka.insert(Either::Left(two_id.clone()));
            reg[&one_id].also_known_as = Some(aka.clone());

            let aka = &mut reg[&two_id].also_known_as.clone().unwrap();
            aka.insert(Either::Left(one_id.clone()));
            reg[&two_id].also_known_as = Some(aka.clone());
        }
    }

    // pub fn generate_verification_method(did: DID, method_name: Option<&str>) -> VerificationMethod {
    //     VerificationMethod {
    //         id:
    //
    //     }
    // }

    pub fn create_random_document(template: Option<Document>) -> Result<Document, anyhow::Error> {
        let mut doc = match template {
            Some(template) => template.clone(),
            None => Default::default(),
        };

        doc.id = create_random_did(None)?;
        Ok(doc)
    }

    pub fn create_random_did(method_name: Option<&str>) -> Result<DID, anyhow::Error> {
        // if a method name is supplied, just use it, otherwise, try to generate a "real" one.
        let method_name: Vec<u8> = match method_name {
            Some(method_name) => method_name.into(),
            None => {
                // this complies with the character limitations in the spec. Create an array of all
                // the valid characters, then select them randomly. Probably could be done better.
                let mut bytes: Vec<u8> = Vec::from((0x61..=0x7a).collect::<Vec<u8>>());
                bytes.append(&mut Vec::from(
                    ('0'..'9').map(|a| a as u8).collect::<Vec<u8>>(),
                ));

                let mut v = Vec::new();

                for _ in 0..rand::random::<usize>() % 100 {
                    let idx = rand::random::<usize>() % bytes.len();
                    v.push(bytes.get(idx).unwrap().clone());
                }

                v
            }
        };

        let mut method_id: [u8; 15] = [0; 15];
        method_id.try_fill(&mut rand::thread_rng())?;

        Ok(DID {
            name: method_name,
            id: method_id.to_vec(),
        })
    }
}

#![allow(dead_code)]

use std::path::PathBuf;
use util::{create_files, create_identities};

#[test]
fn test_generate() {
    let dir = PathBuf::from("/tmp/test");
    std::fs::create_dir_all(dir.clone()).unwrap();
    let reg = create_identities(10, 5).unwrap();
    create_files(PathBuf::from(dir), &reg).unwrap();
}

mod util {
    use std::{collections::BTreeSet, path::PathBuf};

    use did_toolkit::{
        did::DID,
        document::{Document, VerificationMethod, VerificationMethods},
        jwk::JWK,
        registry::Registry,
        url::URLParameters,
    };
    use either::Either;
    use rand::Fill;
    use serde_json::json;
    //use tempfile::tempdir;

    pub fn create_identities<'a>(
        count: usize,
        complexity: usize,
    ) -> Result<Registry, anyhow::Error> {
        let mut reg: Registry = Default::default();

        for _ in 0..count {
            let mut doc = create_random_document(None)?;

            let mut set = BTreeSet::new();
            for num in 0..(rand::random::<usize>() % complexity) {
                set.insert(generate_verification_method(doc.id.clone(), None, num));
            }
            doc.verification_method = Some(set);

            let attrs = &mut [
                &mut doc.authentication,
                &mut doc.assertion_method,
                &mut doc.key_agreement,
                &mut doc.capability_invocation,
                &mut doc.capability_delegation,
            ];

            for x in 0..attrs.len() {
                let mut set = BTreeSet::new();
                let path = &mut [0; 10];
                path.try_fill(&mut rand::thread_rng())?;
                let path = Some(path.to_vec());
                for num in 0..(rand::random::<usize>() % complexity) {
                    set.insert(Either::Left(generate_verification_method(
                        doc.id.clone(),
                        path.clone(),
                        num,
                    )));
                }

                *attrs[x] = Some(VerificationMethods(set));
            }

            if let Err(e) = reg.insert(doc.clone()) {
                eprintln!("Could not generate document {}; skipping: {}", doc.id, e);
            }
        }

        link_documents_aka(&mut reg, complexity);
        link_documents_controller(&mut reg, complexity);

        Ok(reg)
    }

    pub fn create_files(dir: PathBuf, reg: &Registry) -> Result<(), anyhow::Error> {
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

    pub fn generate_verification_method(
        did: DID,
        path: Option<Vec<u8>>,
        num: usize,
    ) -> VerificationMethod {
        VerificationMethod {
            id: did.join(URLParameters {
                path,
                fragment: Some(format!("method-{}", num).as_bytes().to_vec()),
                ..Default::default()
            }),
            controller: did.clone(),
            public_key_jwk: Some(JWK::new()),
            // TODO generate a keypair
            ..Default::default()
        }
    }

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

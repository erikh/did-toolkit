use anyhow::anyhow;
use clap::Parser;
use std::path::PathBuf;
use util::{create_files, create_identities};

#[derive(Parser, Debug)]
#[command(
    author = "Erik Hollensbe <erik+github@hollensbe.org",
    about = "Generate a tree of documents for testing DID parser compliance"
)]
struct Args {
    #[arg(help = "Path to generate files to")]
    path: PathBuf,
    #[arg(
        help = "Number of identities to create",
        short = 'c',
        long = "count",
        default_value = "10"
    )]
    count: usize,
    #[arg(
        help = "Complexity factor: used to calculate inter-linking values and other forms of cross-referencing. Set to less than --count",
        short = 'f',
        long = "complexity-factor",
        default_value = "5"
    )]
    complexity_factor: usize,
    #[arg(
        help = format!("Used to calculate DID maximum length for method name and method ID (indepedently) - max value {}", MAX_DID_LEN),
        short = 'l',
        long = "did-length",
        default_value = "100"
    )]
    max_did_len: usize,
    #[arg(help = "Output CBOR instead of JSON", long = "cbor")]
    cbor: bool,
}

const MAX_DID_LEN: usize = 1000;

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    if args.max_did_len > MAX_DID_LEN {
        return Err(anyhow!("DID lengths cannot be longer than {}", MAX_DID_LEN));
    }

    std::fs::create_dir_all(args.path.clone())?;
    let reg = create_identities(args.count, args.complexity_factor, args.max_did_len)?;
    create_files(args.path, args.cbor, &reg)?;
    Ok(())
}
//
mod util {
    use did_toolkit::{prelude::*, string::url_encoded};
    use either::Either;
    use rand::Fill;
    use serde_json::json;
    use std::{collections::BTreeSet, path::PathBuf};
    use url::Url;

    pub fn create_identities<'a>(
        count: usize,
        complexity: usize,
        max_did_len: usize,
    ) -> Result<Registry, anyhow::Error> {
        let mut reg: Registry = Default::default();

        for _ in 0..count {
            let mut doc = create_random_document(None, max_did_len)?;

            let mut set = BTreeSet::new();
            for num in 0..((rand::random::<usize>() + 1) % complexity) {
                set.insert(generate_verification_method(doc.id.clone(), None, num));
            }
            doc.verification_method = Some(set);

            link_vm_attrs(&mut doc, complexity)?;

            doc.service = Some(create_service_defs(complexity)?);

            if let Err(e) = reg.insert(doc.clone()) {
                eprintln!("Could not generate document {}; skipping: {}", doc.id, e);
            }
        }

        link_documents_aka(&mut reg, complexity);
        link_documents_controller(&mut reg, complexity);

        Ok(reg)
    }

    pub fn create_files(dir: PathBuf, cbor: bool, reg: &Registry) -> Result<(), anyhow::Error> {
        let mut num = 0;

        for (_, doc) in reg.iter() {
            if cbor {
                let filename = dir.join(&format!("{}.cbor", num));
                let mut opts = std::fs::OpenOptions::new();
                opts.create_new(true);
                opts.write(true);
                let io = opts.open(filename)?;
                ciborium::ser::into_writer(doc, io)?;
            } else {
                let filename = dir.join(&format!("{}.json", num));
                std::fs::write(filename, &json!(doc).to_string())?;
            }
            num += 1;
        }

        Ok(())
    }

    pub fn generate_random_url() -> Result<Url, anyhow::Error> {
        let domains = &["example.net", "example.org", "example.com"];
        let mut chars: [u8; 100] = [0; 100];
        chars.try_fill(&mut rand::thread_rng())?;
        let mut path = Vec::new();

        for _ in 0..(rand::random::<usize>() % 30) {
            path.push(chars[rand::random::<usize>() % 100]);
        }

        let path = url_encoded(&path).to_string();
        Ok(Url::parse(&format!(
            "https://{}/{}",
            domains[rand::random::<usize>() % 3],
            path,
        ))?)
    }

    pub fn create_service_defs(
        complexity: usize,
    ) -> Result<BTreeSet<ServiceEndpoint>, anyhow::Error> {
        let mut set = BTreeSet::default();

        for _ in 0..((rand::random::<usize>() + 1) % complexity) {
            let se = ServiceEndpoint {
                id: generate_random_url()?,
                typ: ServiceTypes(Either::Left(ServiceType::LinkedDomains)),
                endpoint: if rand::random::<bool>() {
                    ServiceEndpoints(Either::Left(generate_random_url()?))
                } else {
                    let mut set = BTreeSet::default();

                    for _ in 0..((rand::random::<usize>() + 1) % complexity) {
                        set.insert(generate_random_url()?);
                    }

                    ServiceEndpoints(Either::Right(ServiceEndpointProperties {
                        origins: Some(set),
                        registries: None,
                    }))
                },
            };

            set.insert(se);
        }

        Ok(set)
    }

    pub fn link_vm_attrs(doc: &mut Document, complexity: usize) -> Result<(), anyhow::Error> {
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
            for num in 0..((rand::random::<usize>() + 1) % complexity) {
                let vm = doc.verification_method.clone().unwrap();
                let mut iter = vm.iter();
                if rand::random::<bool>() && iter.len() > 0 {
                    let item = iter.nth(rand::random::<usize>() % iter.len()).unwrap();
                    set.insert(VerificationMethodEither(Either::Right(item.id.clone())));
                } else {
                    set.insert(VerificationMethodEither(Either::Left(
                        generate_verification_method(doc.id.clone(), path.clone(), num),
                    )));
                }
            }

            *attrs[x] = Some(VerificationMethods(set));
        }

        Ok(())
    }

    pub fn link_documents_controller(reg: &mut Registry, iterations: usize) {
        for _ in 0..iterations {
            let one = &mut reg[rand::random::<usize>() % reg.len()].clone();
            let two = reg[rand::random::<usize>() % reg.len()].clone();

            if let None = one.controller {
                reg[&one.id].controller = Some(Controller(Either::Left(two.id)));
            } else {
                match one.controller.clone().unwrap().0 {
                    Either::Left(did) => {
                        if did != two.id {
                            let mut set = BTreeSet::new();
                            set.insert(did);
                            set.insert(two.id);
                            reg[&one.id].controller = Some(Controller(Either::Right(set)));
                        }
                    }
                    Either::Right(mut set) => {
                        set.insert(two.id);
                        reg[&one.id].controller = Some(Controller(Either::Right(set)));
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
                one.also_known_as = Some(AlsoKnownAs::default());
            }

            if let None = two.also_known_as {
                let two = &mut reg[&two_id];
                two.also_known_as = Some(AlsoKnownAs::default());
            }

            let aka = &mut reg[&one_id].also_known_as.clone().unwrap();
            aka.0
                .insert(AlsoKnownAsEither(Either::Left(two_id.clone())));
            reg[&one_id].also_known_as = Some(aka.clone());

            let aka = &mut reg[&two_id].also_known_as.clone().unwrap();
            aka.0
                .insert(AlsoKnownAsEither(Either::Left(one_id.clone())));
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
            public_key_jwk: Some(JWK::new().unwrap()),
            // TODO generate a keypair
            ..Default::default()
        }
    }

    pub fn create_random_document(
        template: Option<Document>,
        max_did_len: usize,
    ) -> Result<Document, anyhow::Error> {
        let mut doc = match template {
            Some(template) => template.clone(),
            None => Default::default(),
        };

        doc.id = create_random_did(None, max_did_len)?;
        Ok(doc)
    }

    pub fn create_random_did(
        method_name: Option<&str>,
        max_len: usize,
    ) -> Result<DID, anyhow::Error> {
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

                for _ in 0..(((rand::random::<usize>() + 1) % max_len) + 1) {
                    let idx = rand::random::<usize>() % bytes.len();
                    v.push(bytes.get(idx).unwrap().clone());
                }

                v
            }
        };

        let mut chars: [u8; 1000] = [0; 1000];
        chars.try_fill(&mut rand::thread_rng())?;

        let mut method_id = Vec::new();
        for x in 0..(((rand::random::<usize>() + 1) % max_len) + 1) {
            method_id.push(chars[x]);
        }

        Ok(DID {
            name: method_name,
            id: method_id,
        })
    }
}

use std::collections::BTreeMap;

use crate::{did::DID, document::Document};

pub struct Registry(BTreeMap<DID, Document>);

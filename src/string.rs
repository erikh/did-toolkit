use anyhow::anyhow;

/// Encode portions of the URL according to https://www.w3.org/TR/did-core/#did-syntax
pub fn url_encoded(input: &[u8]) -> String {
    let mut ret: Vec<u8> = Vec::new();

    for idx in input {
        match *idx as char {
            '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '-' | '_' => ret.push(*idx),
            _ => {
                for i in format!("%{:02X}", idx).bytes() {
                    ret.push(i)
                }
            }
        }
    }

    String::from_utf8(ret).unwrap()
}

/// Decode portions of the URL according to https://www.w3.org/TR/did-core/#did-syntax
pub fn url_decoded(s: &str) -> Vec<u8> {
    let mut hexval: u8 = 0;
    let mut hexleft = true;
    let mut ret = Vec::new();
    let mut in_pct = false;

    for idx in s.bytes() {
        match idx as char {
            '%' => in_pct = true,
            '0'..='9' | 'a'..='f' | 'A'..='F' => {
                if in_pct {
                    let val: u8 = (idx as char).to_digit(16).unwrap() as u8;

                    hexval |= if hexleft { val << 4 } else { val };

                    if hexleft {
                        hexleft = false;
                    } else {
                        ret.push(hexval);
                        in_pct = false;
                        hexleft = true;
                        hexval = 0;
                    }
                } else {
                    ret.push(idx)
                }
            }
            _ => ret.push(idx),
        }
    }

    ret
}

/// Validate method names fit within the proper ASCII range according to
/// https://www.w3.org/TR/did-core/#did-syntax. Return an error if any characters fall outside of
/// it.
pub fn validate_method_name(s: &str) -> Result<(), anyhow::Error> {
    for idx in s.bytes() {
        if idx < 0x61 || idx > 0x7a {
            return Err(anyhow!(
                "Method name has invalid characters (not in 0x61 - 0x7a)"
            ));
        }
    }

    Ok(())
}

mod tests {
    #[test]
    fn test_encode_decode() {
        let encoded = super::url_encoded("text with spaces".as_bytes());
        assert_eq!(encoded, String::from("text%20with%20spaces"));
        assert_eq!(super::url_decoded(&encoded), "text with spaces".as_bytes());
    }

    #[test]
    fn test_battery_encode() {
        use rand::Fill;

        let mut rng = rand::thread_rng();

        for _ in 1..100000 {
            let mut array: [u8; 100] = [0; 100];
            array.try_fill(&mut rng).unwrap();
            let encoded = super::url_encoded(&array);
            assert_eq!(super::url_decoded(&encoded), array, "{}", encoded);
        }
    }

    #[test]
    fn test_validate_method_name() {
        assert!(super::validate_method_name("erik").is_ok());
        assert!(super::validate_method_name("not valid").is_err());
    }
}

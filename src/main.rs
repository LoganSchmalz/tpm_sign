use std::{
    fs::File,
    io::{Read, Write},
};

use picky_asn1_x509::SubjectPublicKeyInfo;
use tss_esapi::{
    abstraction::public::DecodedKey,
    attributes::{ObjectAttributes, ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Auth, Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, MaxBuffer,
        PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme, RsaSignature, Signature, SignatureScheme, SymmetricCipherParameters,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf,
};

use std::convert::TryFrom;
use std::env;
use std::error;
use std::fmt;
use std::time::Instant;

#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    Esapi(tss_esapi::Error),
    PickyAsn1Der(picky_asn1_der::Asn1DerError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "IO Error: {}", e),
            Error::Esapi(ref e) => write!(f, "ESAPI Error: {}", e),
            Error::PickyAsn1Der(ref e) => write!(f, "Picky ASN1 DER Error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Esapi(ref e) => Some(e),
            Error::PickyAsn1Der(ref e) => Some(e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(err: tss_esapi::Error) -> Error {
        Error::Esapi(err)
    }
}

impl From<picky_asn1_der::Asn1DerError> for Error {
    fn from(err: picky_asn1_der::Asn1DerError) -> Error {
        Error::PickyAsn1Der(err)
    }
}

fn provision(auth_digest_path: Option<&str>) -> Result<(), Error> {
    let mut context = Context::new(TctiNameConf::from_environment_variable()?)?;
    let auth_session = create_basic_auth_session(&mut context, SessionType::Hmac)?;
    context.set_sessions((Some(auth_session), None, None));

    let primary_key_handle = create_primary_handle(&mut context)?;

    let auth_digest = auth_digest_path
        .map(read_file_to_buf)
        .transpose()?
        .map(Digest::try_from)
        .transpose()?;

    let (_, public) = create_signing_handle(
        &mut context,
        primary_key_handle,
        "key.pub",
        "key.priv",
        auth_digest,
    );
    create_public_der(public, "key.der");

    Ok(())
}

fn dump_public_key() -> Result<(), Error> {
    let public = Public::unmarshall(&read_file_to_buf("key.pub")?)?;
    create_public_der(public, "key.der");
    Ok(())
}

fn load_external_signing_key(context: &mut Context) -> Result<KeyHandle, Error> {
    let der = read_file_to_buf("policy/policy_key.der")?;
    let key: picky_asn1_x509::RsaPublicKey = picky_asn1_der::from_bytes(&der)?;
    let modulus = key.modulus.as_unsigned_bytes_be();
    let exponent = key
        .public_exponent
        .as_unsigned_bytes_be()
        .iter()
        .enumerate()
        .fold(0u32, |v, (i, &x)| v + ((x as u32) << (8 * i as u32)));

    let public_policy_key = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::try_from(modulus.len() as u16 * 8)?)
                .with_exponent(RsaExponent::create(exponent)?)
                .build()?,
        )
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_sign_encrypt(true)
                .with_decrypt(true)
                .with_user_with_auth(true)
                .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::try_from(modulus)?)
        .build()?;

    let policy_key_handle = context
        .load_external_public(public_policy_key, Hierarchy::Owner)
        .unwrap();

    Ok(policy_key_handle)
}

fn run() -> Result<(), Error> {
    let mut benchmark = vec![("", Instant::now())];
    let mut context = Context::new(TctiNameConf::from_environment_variable()?)?;
    benchmark.push(("Context", Instant::now()));

    let policy_key_handle = load_external_signing_key(&mut context)?;
    let key_sign = context.tr_get_name(policy_key_handle.into()).unwrap();
    benchmark.push(("Policy Key", Instant::now()));
    let approved_policy = Digest::try_from(read_file_to_buf("policy/pcr.policy_desired")?)?;
    let policy_digest = context
        .hash(
            MaxBuffer::try_from(approved_policy.value())?,
            HashingAlgorithm::Sha256,
            Hierarchy::Null,
        )?
        .0;
    benchmark.push(("Policy Digest", Instant::now()));
    let policy_signature = Signature::RsaSsa(RsaSignature::create(
        HashingAlgorithm::Sha256,
        PublicKeyRsa::try_from(read_file_to_buf("policy/pcr.signature")?)?,
    )?);
    let check_ticket =
        context.verify_signature(policy_key_handle, policy_digest, policy_signature)?;
    benchmark.push(("Policy Verified", Instant::now()));

    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
        .build()?;

    let (_update_counter, _pcr_list_out, pcr_digests) =
        context.pcr_read(pcr_selection_list.clone())?;
    let concatenated_pcr_values = pcr_digests
        .value()
        .iter()
        .map(|v| v.value())
        .collect::<Vec<&[u8]>>()
        .concat();
    println!("{:?}", pcr_digests);
    let hashed_pcrs = context
        .hash(
            MaxBuffer::try_from(concatenated_pcr_values.to_vec())?,
            HashingAlgorithm::Sha256,
            Hierarchy::Null,
        )?
        .0;

    let auth_session = create_basic_auth_session(&mut context, SessionType::Hmac)?;
    context.set_sessions((Some(auth_session), None, None));
    let primary_key_handle = create_primary_handle(&mut context)?;
    benchmark.push(("Primary", Instant::now()));
    context.clear_sessions();

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .unwrap(); // TODO: fix unwrap here
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
    let policy_session: PolicySession = session.try_into()?;

    context.policy_pcr(policy_session, hashed_pcrs, pcr_selection_list.clone())?;
    let digest = context.policy_get_digest(policy_session)?;
    println!("{:?}", digest);

    let approved_policy = Digest::try_from(read_file_to_buf("policy/pcr.policy_desired")?)?;
    context.policy_authorize(
        policy_session,
        approved_policy,
        Default::default(),
        &key_sign,
        check_ticket,
    )?;

    let policy_auth_digest = context.policy_get_digest(session.try_into()?)?;
    println!("{:?}", policy_auth_digest);

    context.set_sessions((Some(session), None, None));

    let public = Public::unmarshall(&read_file_to_buf("key.pub")?)?;
    let private = Private::try_from(read_file_to_buf("key.priv")?)?;
    let key_handle = context.load(primary_key_handle, private, public)?;

    benchmark.push(("Signing", Instant::now()));

    let msg = MaxBuffer::try_from("TPMs are cool.".repeat(73).as_bytes().to_vec())?;

    // executing without a session is fastest and allowed for hashing
    let (digest, ticket) = context
        .execute_without_session(|ctx| ctx.hash(msg, HashingAlgorithm::Sha256, Hierarchy::Owner))
        .unwrap();
    benchmark.push(("Hash", Instant::now()));

    let signature = context
        .sign(
            key_handle,
            digest.clone(),
            SignatureScheme::RsaPss {
                //SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            ticket,
        )
        .unwrap();
    benchmark.push(("Sign", Instant::now()));

    // executing without a session is fastest and allowed for verifying
    let verified_data =
        context.execute_without_session(|ctx| ctx.verify_signature(key_handle, digest, signature));
    benchmark.push(("Verify", Instant::now()));

    for i in 1..benchmark.len() {
        eprintln!(
            "{:<16} {:?}",
            format!("{}:", benchmark[i].0),
            benchmark[i].1 - benchmark[i - 1].1
        );
    }
    eprintln!("{:?}", benchmark[benchmark.len() - 1].1 - benchmark[0].1);

    assert!(verified_data.is_ok());

    Ok(())
}

fn create_basic_auth_session(
    context: &mut Context,
    session_type: SessionType,
) -> Result<AuthSession, Error> {
    let auth_session = context.start_auth_session(
        None,
        None,
        None,
        session_type,
        SymmetricDefinition::AES_128_CFB,
        //HashingAlgorithm::Sha256,
        HashingAlgorithm::Sha256,
    )?;
    if let Some(auth_session) = auth_session {
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        context.tr_sess_set_attributes(
            auth_session,
            session_attributes,
            session_attributes_mask,
        )?;
    }
    // TODO: potential bad case when context.start_auth_session returns None

    Ok(auth_session.unwrap())
}

fn create_primary_handle(context: &mut Context) -> Result<KeyHandle, Error> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()?;

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()?;

    let result = context.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)?;

    Ok(result.key_handle)
}

fn create_signing_handle(
    context: &mut Context,
    primary_key_handle: KeyHandle,
    pub_key_path: &str,
    priv_key_path: &str,
    auth_digest: Option<Digest>,
) -> (KeyHandle, Public) {
    let mut pub_file = File::create_new(pub_key_path).unwrap_or_else(|_| {
        panic!(
            "Error: Public key file {} already exists, not reprovisioning",
            pub_key_path
        )
    });
    let mut priv_file = File::create_new(priv_key_path).unwrap_or_else(|_| {
        panic!(
            "Error: Private key file {} already exists, not reprovisioning",
            priv_key_path
        )
    });

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let key_pub = create_signing_key_rsa(object_attributes, auth_digest.clone()).unwrap();
    //let key_pub = create_signing_key_ecc(object_attributes, auth_digest);

    let (private, public) = context
        .create(
            primary_key_handle,
            key_pub,
            auth_digest.map(|d| Auth::try_from(d.value()).unwrap()),
            None,
            None,
            None,
        )
        .map(|key| (key.out_private, key.out_public))
        .unwrap();

    let key_handle = context
        .load(primary_key_handle, private.clone(), public.clone())
        .unwrap();

    pub_file.write_all(&public.marshall().unwrap()).unwrap();
    priv_file.write_all(&private).unwrap();

    (key_handle, public)
}

#[allow(dead_code)]
fn create_signing_key_rsa(
    object_attributes: ObjectAttributes,
    auth_digest: Option<Digest>,
) -> Result<Public, Error> {
    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        // disallow decryption since allowing both is vulnerable to attacks
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()?;

    let public_builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default());
    let public_builder = if let Some(digest) = auth_digest {
        println!("Auth digest required: {:?}", digest);
        public_builder.with_auth_policy(digest)
    } else {
        public_builder
    };
    Ok(public_builder.build()?)
}

#[allow(dead_code)]
fn create_signing_key_ecc(
    object_attributes: ObjectAttributes,
    auth_digest: Option<Digest>,
) -> Result<Public, Error> {
    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP384)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .with_restricted(true)
        .build()?;

    let public_builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default());
    let public_builder = if let Some(digest) = auth_digest {
        public_builder.with_auth_policy(digest)
    } else {
        public_builder
    };
    Ok(public_builder.build()?)
}

fn create_public_der(public: Public, pub_der_path: &str) {
    let mut pub_der = File::create_new(pub_der_path).unwrap_or_else(|_| {
        panic!(
            "Error: Public key DER file {} already exists, not overwriting",
            pub_der_path
        )
    });
    let decoded_key =
        DecodedKey::try_from(public).expect("Failed to convert Public structure to DecodedKey");

    let buf = match decoded_key {
        DecodedKey::EcPoint(key) => {
            // TODO: SubjectPublicKeyInfo handling
            picky_asn1_der::to_vec(&key).unwrap()
        }
        DecodedKey::RsaPublicKey(key) => {
            let key = SubjectPublicKeyInfo::new_rsa_key(key.modulus, key.public_exponent);
            picky_asn1_der::to_vec(&key).unwrap()
        }
    };
    assert!(!buf.is_empty());
    pub_der.write_all(&buf).unwrap();
}

fn read_file_to_buf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.len() {
        0 => run(),
        1 => match args[0].as_str() {
            //"provision" => provision(None),
            "provision" => provision(Some("policy/authorized.policy")),
            "public_key" => dump_public_key(),
            _ => panic!("Invalid argument provided"),
        },
        _ => panic!(
            "Too many arguments: 0 or 1 expected, {} provided",
            args.len()
        ),
    }
}

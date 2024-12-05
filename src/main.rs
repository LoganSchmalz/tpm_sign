use std::{fs, io, path::Path};

use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        SessionType,
    },
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        Digest, HashScheme, HashcheckTicket, MaxBuffer, Nonce, PcrSelectionListBuilder, PcrSlot,
        Private, Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme, RsaSignature, Signature, SignatureScheme, SymmetricCipherParameters,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::UnMarshall,
    tss2_esys::TPMT_TK_HASHCHECK,
    Context, TctiNameConf,
};

use std::convert::TryFrom;
use std::env;
use std::error;
use std::fmt;
use std::time::Instant;

#[derive(Debug)]
enum Error {
    Slicing,
    Io(io::Error),
    Esapi(tss_esapi::Error),
    OpenSsl(openssl::error::ErrorStack),
    SerdeJson(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Slicing => write!(f, "Slicing Error"),
            Self::Io(ref e) => write!(f, "IO Error: {e}"),
            Self::Esapi(ref e) => write!(f, "ESAPI Error: {e}"),
            Self::OpenSsl(ref e) => write!(f, "OpenSSL Error: {e}"),
            Self::SerdeJson(ref e) => write!(f, "Serde Json Error: {e}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Slicing => None,
            Self::Io(ref e) => Some(e),
            Self::Esapi(ref e) => Some(e),
            Self::OpenSsl(ref e) => Some(e),
            Self::SerdeJson(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(err: tss_esapi::Error) -> Self {
        Self::Esapi(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSsl(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::SerdeJson(err)
    }
}

fn load_external_signing_key(context: &mut Context) -> Result<KeyHandle, Error> {
    let der = fs::read("policy/policy_key.pem")?;
    let key = openssl::rsa::Rsa::public_key_from_pem(&der)?;
    let modulus = key.n().to_vec();
    let exponent = key
        .e()
        .to_vec()
        .iter()
        .enumerate()
        .fold(0u32, |v, (i, &x)| v + (u32::from(x) << (8 * i as u32)));

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

    let policy_key_handle = context.load_external_public(public_policy_key, Hierarchy::Owner)?;

    Ok(policy_key_handle)
}

#[deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
fn run(use_key_context: bool) -> Result<(), Error> {
    let mut benchmark = vec![("", Instant::now())];
    let mut context = Context::new(TctiNameConf::from_environment_variable()?)?;
    benchmark.push(("Context", Instant::now()));

    let approved_policy = Digest::try_from(fs::read("policy/pcr.policy_desired")?)?;
    let policy_digest = context
        .hash(
            MaxBuffer::try_from(approved_policy.value())?,
            HashingAlgorithm::Sha256,
            Hierarchy::Null,
        )?
        .0;
    benchmark.push(("Policy Digest", Instant::now()));

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::WrongValueFromTpm,
        ))?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
    let policy_session: PolicySession = session.try_into()?;
    set_policy(&mut context, policy_session)?;

    let policy_key_handle = if use_key_context {
        if let Ok(key_handle) = reload_key_context(&mut context, env::temp_dir().join("policy.ctx"))
        {
            key_handle
        } else {
            let policy_key_handle = load_external_signing_key(&mut context)?;
            let _ = save_key_context(
                &mut context,
                policy_key_handle.into(),
                env::temp_dir().join("policy.ctx"),
            );
            policy_key_handle
        }
    } else {
        load_external_signing_key(&mut context)?
    };
    let key_sign = context.tr_get_name(policy_key_handle.into())?;
    benchmark.push(("Policy Key", Instant::now()));

    let policy_signature = Signature::RsaSsa(RsaSignature::create(
        HashingAlgorithm::Sha256,
        PublicKeyRsa::try_from(fs::read("policy/pcr.signature")?)?,
    )?);
    let check_ticket =
        context.verify_signature(policy_key_handle, policy_digest, policy_signature)?;
    benchmark.push(("Policy Verified", Instant::now()));
    // policy_key_handle is no longer necessary and keeping it loaded slows things down
    context.flush_context(policy_key_handle.into())?;

    context.policy_authorize(
        policy_session,
        approved_policy,
        Nonce::default(),
        &key_sign,
        check_ticket,
    )?;
    //let policy_auth_digest = context.policy_get_digest(policy_session)?;
    //println!("{:?}", policy_auth_digest);
    benchmark.push(("Policy Set", Instant::now()));

    let msg = MaxBuffer::try_from("TPMs are cool.".repeat(73).as_bytes().to_vec())?;

    // executing without a session is fastest and allowed for hashing
    //let (digest, ticket) = context.execute_without_session(|ctx| {
    //    ctx.hash(msg.clone(), HashingAlgorithm::Sha256, Hierarchy::Owner)
    //})?;
    let digest = openssl::sha::sha256(&msg).to_vec();
    let digest = Digest::try_from(digest)?;
    benchmark.push(("Hash", Instant::now()));

    let key_handle = load_signing_key(&mut context, use_key_context)?;
    benchmark.push(("Signing Key", Instant::now()));

    let signature = context.execute_with_session(Some(session), |context| {
        context.sign(
            key_handle,
            digest.clone(),
            SignatureScheme::RsaPss {
                //SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            // temporary workaround because validation is erroneously non-optional in tss_esapi v7.5.1
            HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
                tag: TPM2_ST_HASHCHECK,
                hierarchy: TPM2_RH_NULL,
                digest: Default::default(),
            })?,
        )
    })?;
    benchmark.push(("Sign", Instant::now()));

    // executing without a session is fastest and allowed for verifying
    //let verified_data = context
    //    .execute_without_session(|ctx| ctx.verify_signature(key_handle, digest, signature.clone()));
    benchmark.push(("Verify", Instant::now()));

    {
        #![expect(clippy::unwrap_used)]
        #![expect(clippy::panic)]
        let pkey = openssl::pkey::PKey::public_key_from_pem(&fs::read("key.pem")?).unwrap();
        let signature = match signature {
            Signature::RsaSsa(sig) | Signature::RsaPss(sig) => sig.signature().value().to_vec(),
            _ => {
                panic!("really bad");
            }
        };
        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
        verifier
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        let res = verifier.verify_oneshot(&signature, msg.value()).unwrap();
        println!("{res}");
        assert!(res);
    }

    {
        #![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
        for i in 1..benchmark.len() {
            eprintln!(
                "{:<16} {:?}",
                format!("{}:", benchmark[i].0),
                benchmark[i].1 - benchmark[i - 1].1
            );
        }
        eprintln!("{:?}", benchmark[benchmark.len() - 1].1 - benchmark[0].1);
    }

    //assert!(verified_data.is_ok());

    Ok(())
}

fn set_policy(context: &mut Context, session: PolicySession) -> Result<(), Error> {
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
        .build()?;

    let (_update_counter, _pcr_list_out, pcr_digests) =
        context.pcr_read(pcr_selection_list.clone())?;
    let concatenated_pcr_values = pcr_digests
        .value()
        .iter()
        .map(Digest::value)
        .collect::<Vec<&[u8]>>()
        .concat();

    let hashed_pcrs = context
        .hash(
            MaxBuffer::try_from(concatenated_pcr_values)?,
            HashingAlgorithm::Sha256,
            Hierarchy::Null,
        )?
        .0;

    context.policy_pcr(session, hashed_pcrs, pcr_selection_list)?;

    Ok(())
}

fn reload_key_context<P: AsRef<Path>>(
    context: &mut Context,
    context_path: P,
) -> Result<KeyHandle, Error> {
    let buf = fs::read(context_path)?;
    let ctx = serde_json::from_slice(&buf)?;
    Ok(context.context_load(ctx)?.into())
}

fn save_key_context<P: AsRef<Path>>(
    context: &mut Context,
    handle: ObjectHandle,
    path: P,
) -> Result<(), Error> {
    let policy_context = context.context_save(handle)?;
    fs::write(path, serde_json::to_vec(&policy_context)?)?;
    Ok(())
}

fn load_signing_key(context: &mut Context, use_key_context: bool) -> Result<KeyHandle, Error> {
    if use_key_context {
        if let Ok(key_handle) = reload_key_context(context, env::temp_dir().join("signing.ctx")) {
            return Ok(key_handle);
        }
    }

    let old_session_handles = context.sessions();

    let auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::WrongValueFromTpm,
        ))?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(auth_session, session_attributes, session_attributes_mask)?;

    context.set_sessions((Some(auth_session), None, None));
    let primary_key_handle = create_primary_handle(context)?;
    let public = Public::unmarshall(fs::read("key.pub")?.get(2..).ok_or(Error::Slicing)?)?;
    let private = Private::try_from(fs::read("key.priv")?.get(2..).ok_or(Error::Slicing)?)?;
    let key_handle = context.load(primary_key_handle, private, public)?;
    // primary_key_handle is no longer necessary and keeping it loaded slows things down
    context.flush_context(primary_key_handle.into())?;
    context.set_sessions(old_session_handles);

    if use_key_context {
        let _ = save_key_context(
            context,
            key_handle.into(),
            env::temp_dir().join("signing.ctx"),
        );
    }

    Ok(key_handle)
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

fn main() -> Result<(), Error> {
    #![expect(clippy::panic)]
    let args: Vec<String> = env::args().skip(1).collect();
    match args.len() {
        0 => run(true),
        _ => panic!("Too many arguments: 0 expected, {} provided", args.len()),
    }
}

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, HashScheme, MaxBuffer, PublicBuilder, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaExponent, RsaScheme, SignatureScheme,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    Context, TctiNameConf,
};

use std::convert::TryFrom;

fn main() -> std::io::Result<()> {
    let mut context = Context::new(TctiNameConf::from_environment_variable().expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`")).expect("Failed to create Context");

    let primary = create_primary(&mut context);

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // disallow decryption since allowing both is vulnerable to attacks
        .with_decrypt(false)
        .with_sign_encrypt(true)
        // making a signing key restricted is actually okay because the TPM can distinguish
        // between TPM generated data (e.g. PCR quotes) and non-TPM generated data (our use case)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()
        .expect("Failed to build rsa parameters");

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .unwrap();

    let (sign_private, public) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))
        })
        .unwrap();

    let key_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.load(primary.key_handle, sign_private.clone(), public.clone())
        })
        .unwrap();

    //let message = "TPMs are cool.".repeat(73).as_bytes().to_vec();
    let message = "T".repeat(1024).as_bytes().to_vec();
    //let message = vec![0xff, b'T', b'C', b'G'];
    let (digest, ticket) = if message.len() <= 1024 {
        let data_to_sign =
            MaxBuffer::try_from(message).expect("Failed to create buffer for data to sign.");
        context
            .execute_with_nullauth_session(|ctx| {
                ctx.hash(
                    data_to_sign.clone(),
                    HashingAlgorithm::Sha256,
                    Hierarchy::Owner, // cannot be Hierarchy::Null if signing key is restricted because it will not generate a valid ticket
                )
            })
            .unwrap()
    } else {
        todo!("Requires Context::hash_sequence_start and related functions to be implemented in tss-esapi.")
    };

    println!("digest = {:?}", digest);
    println!("ticket = {:?}", ticket);

    let signature = context
        .execute_with_nullauth_session(|ctx| {
            ctx.sign(
                key_handle,
                digest.clone(),
                SignatureScheme::RsaPss {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                ticket.clone(),
            )
        })
        .unwrap();
    println!("signature = {:?}", signature);

    let verified_data = context.execute_with_nullauth_session(|ctx| {
        ctx.verify_signature(key_handle, digest.clone(), signature.clone())
    });
    println!("verified_data = {:?}", verified_data);

    // This assertion will fail if the signature was not successfully verified
    assert!(verified_data.is_ok());

    Ok(())
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap()
}

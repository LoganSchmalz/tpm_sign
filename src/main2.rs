use std::{fs::File, io::Write};

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Data, Digest, HashScheme, MaxBuffer, PublicBuilder, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaExponent, RsaScheme, SignatureScheme,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    utils::TpmsContext,
    Context, TctiNameConf,
};

use std::convert::TryFrom;

fn main() -> std::io::Result<()> {
    let mut context = Context::new(TctiNameConf::from_environment_variable().expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`")).expect("Failed to create Context");

    let primary_key_handle = create_primary_handle(&mut context);
    println!(
        "primary_public = {:?}",
        context.read_public(primary_key_handle)
    );

    let key_handle = primary_key_handle;

    //let key_handle = create_signing_handle(&mut context, primary_key_handle);

    let data_to_sign = MaxBuffer::try_from("TPMs are cool.".repeat(73).as_bytes().to_vec())
        .expect("Failed to create buffer for data to sign.");

    let (digest, ticket) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.hash(
                data_to_sign.clone(),
                HashingAlgorithm::Sha512,
                Hierarchy::Null,
            )
        })
        .unwrap();
    //println!("digest = {:?}", digest);

    let signature = context
        .execute_with_nullauth_session(|ctx| {
            ctx.sign(
                key_handle,
                digest.clone(),
                SignatureScheme::RsaPss {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha512),
                },
                ticket.clone(),
            )
        })
        .unwrap();
    println!("signature = {:?}", signature);

    let verified_data = context
        .execute_with_nullauth_session(|ctx| {
            ctx.verify_signature(key_handle, digest.clone(), signature.clone())
        })
        .unwrap();
    println!("verified_data = {:?}", verified_data);

    Ok(())
}

fn create_primary_handle(context: &mut Context) -> KeyHandle {
    let index = 0x81000000;
    let persistent_tpm_handle = PersistentTpmHandle::new(index).unwrap();

    if let Ok(key_handle) = context
        .execute_with_nullauth_session(|ctx| ctx.tr_from_tpm_public(persistent_tpm_handle.into()))
    {
        return key_handle.into();
    }

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        // Note that we don't set the key as restricted.
        .build()
        .expect("Failed to build object attributes");

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .with_restricted(false)
        .build()
        .expect("Failed to build rsa parameters");

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha512)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .unwrap();

    let result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_pub,
                None,
                None,
                Some(Data::try_from("test".as_bytes()).unwrap()),
                None,
            )
        })
        .unwrap();

    let persistent = Persistent::Persistent(persistent_tpm_handle);

    let result2 = context
        .execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                tss_esapi::interface_types::resource_handles::Provision::Owner,
                result.key_handle.into(),
                persistent,
            )
        })
        .expect("Failed to make primary key handle persistent");

    println!("key saved to index {:#x}", index);

    result2.into()
}

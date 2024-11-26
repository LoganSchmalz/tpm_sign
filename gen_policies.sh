#!/bin/sh

mkdir -p policy
cd policy
# generate OpenSSL key (don't make a new key if one already exists)
if [ ! -f signing_key_private.pem ]
then
	openssl genrsa -out signing_key_private.pem 2048
	openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout
fi
# dump the public portion as a der for loading in my Rust program
openssl rsa -pubin -in signing_key_public.pem -inform PEM -outform DER -out policy_key.der -RSAPublicKey_out
# load the public portion for authorized digest creation
tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name
# create authorized policy digest
tpm2_startauthsession -S session.ctx
tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name
tpm2_flushcontext session.ctx
# create a PCR policy and sign it
tpm2_pcrread -opcr0.sha256 sha256:0
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:0 -f pcr0.sha256 -L pcr.policy_desired
tpm2_flushcontext session.ctx
openssl dgst -sha256 -sign signing_key_private.pem -out pcr.signature pcr.policy_desired

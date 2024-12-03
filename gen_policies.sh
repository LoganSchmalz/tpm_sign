#!/bin/sh

mkdir -p policy
cd policy
# generate OpenSSL key (don't make a new key if one already exists)
if [ ! -f policy_key_private.pem ]
then
	openssl genrsa -out policy_key_private.pem 2048
	openssl rsa -in policy_key_private.pem -out policy_key.pem -pubout
fi
# load the public portion for authorized digest creation
tpm2_loadexternal -G rsa -C o -u policy_key.pem -c policy_key.ctx -n policy_key.name
# create authorized policy digest
tpm2_startauthsession -S session.ctx
tpm2_policyauthorize -S session.ctx -L authorized.policy -n policy_key.name
tpm2_flushcontext session.ctx
# create a PCR policy and sign it
tpm2_pcrread -opcr0.sha256 sha256:0
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:0 -f pcr0.sha256 -L pcr.policy_desired
tpm2_flushcontext session.ctx
openssl dgst -sha256 -sign policy_key_private.pem -out pcr.signature pcr.policy_desired

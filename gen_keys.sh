#!/bin/sh
if [ ! -f key.pem ] && [ -f key.pub ] && [ -f key.priv ] 
then
	echo "missing key.pem, recreating from existing key"
	tpm2_createprimary -C o -g sha256 -G aes128cfb -c prim.ctx > /dev/null
	tpm2_load -u key.pub -r key.priv -C prim.ctx -c signing.ctx  > /dev/null
	tpm2_readpublic -c signing.ctx -o key.pem --format=pem > /dev/null
	rm prim.ctx signing.ctx
	exit 0
fi
if [ -f key.pub ] || [ -f key.priv ]
then
	echo "key.pub and/or key.priv already exists, not reprovisioning"
	exit 1
fi

tpm2_createprimary -C o -g sha256 -G aes128cfb -c prim.ctx
tpm2_create -u key.pub -r key.priv -g sha256 -G "rsa2048:rsapss:null" -a "sign|fixedtpm|fixedparent|sensitivedataorigin" -C prim.ctx -c signing.ctx -L policy/authorized.policy
tpm2_readpublic -c signing.ctx -o key.pem --format=pem
rm prim.ctx signing.ctx

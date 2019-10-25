OUT_DIR=./tpmout
if [ -d $OUT_DIR ]; then
    rm -rf $OUT_DIR
fi

mkdir $OUT_DIR

tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef

tpm2_createprimary -H o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -g 0x000B -G 0x0001 -C $OUT_DIR/primaryKey.context

tpm2_evictcontrol -A o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -c $OUT_DIR/primaryKey.context -S 0x81000000

tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f $OUT_DIR/endorsementKey

tpm2_readpublic -H 0x81010000 -o $OUT_DIR/endorsementkeyecpub

tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -E 0x81010000 -k 0x81018000 -f $OUT_DIR/aik -n $OUT_DIR/aikName -g 0x1 -D 0x000B -s 0x14

echo "======================="
echo "12345678" > $OUT_DIR/secret.data
file_size=`stat --printf="%s" $OUT_DIR/aikName`
AK_NAME_STRING=`cat "$OUT_DIR/aikName" | xxd -p -c $file_size`
tpm2_makecredential -e $OUT_DIR/endorsementkeyecpub -s $OUT_DIR/secret.data -n $AK_NAME_STRING -o $OUT_DIR/makecredential.out

echo "======================="
tpm2_activatecredential -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -H 0x81018000 -k 0x81010000 -f $OUT_DIR/makecredential.out -o $OUT_DIR/decrypted.out

tpm2_create -H 0x81000000 -g 0x0B -G 0x1 -A 0x00020072 -u tpmout/bindingKey.pub -r tpmout/bindingKey.priv -K hex:12345678
tpm2_load -H 0x81000000 -u tpmout/bindingKey.pub -r tpmout/bindingKey.priv -C tpmout/bk.context -n tpmout/bkFilename
tpm2_certify -k 0x81018000 -H 0x81000000 -K hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -g 0x0B -a tpmout/out.attest -s tpmout/out.sig -C tpmout/bk.context -P hex:12345678
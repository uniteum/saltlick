source .env
bytecode=$(forge inspect SaltLick bytecode)
constructorArgs=$(cast abi-encode "constructor(address)" $owner)
initcode=$(cast concat-hex $bytecode $constructorArgs)
initcodehash=$(cast keccak $initcode)
echo "initcodehash=$initcodehash"
input=$(cast concat-hex $salt $initcode)
printf '%s' "$input" > script/SaltLick.txt
SaltLick=$(cast create2 --deployer $deployer --salt $salt --init-code $initcode)
echo "SaltLick=$SaltLick"
forge verify-contract $SaltLick SaltLick --verifier etherscan --show-standard-json-input | jq '.'> script/SaltLick.json

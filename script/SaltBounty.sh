source .env
bytecode=$(forge inspect SaltBounty bytecode)
constructorArgs=$(cast abi-encode "constructor(address)" $owner)
initcode=$(cast concat-hex $bytecode $constructorArgs)
initcodehash=$(cast keccak $initcode)
echo "initcodehash=$initcodehash"
input=$(cast concat-hex $salt $initcode)
printf '%s' "$input" > script/SaltBounty.txt
SaltBounty=$(cast create2 --deployer $deployer --salt $salt --init-code $initcode)
echo "SaltBounty=$SaltBounty"
forge verify-contract $SaltBounty SaltBounty --verifier etherscan --show-standard-json-input | jq '.'> script/SaltBounty.json

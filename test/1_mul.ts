import { compile, acir_from_bytes, acir_to_bytes } from '@noir-lang/noir_wasm';
import { setup_generic_prover_and_verifier, create_proof, verify_proof, create_proof_with_witness } from '@noir-lang/barretenberg/dest/client_proofs';
import { packed_witness_to_witness, serialise_public_inputs, compute_witnesses } from '@noir-lang/aztec_backend';
import path from 'path';
import { readFileSync } from 'fs';
import { expect } from 'chai';
import { ethers } from "hardhat";
import { Contract, ContractFactory, utils } from 'ethers';
import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { SinglePedersen } from '@noir-lang/barretenberg/dest/crypto/pedersen';

describe("1_mul", function() {
    let barretenberg: BarretenbergWasm;
    let pedersen: SinglePedersen;

    before(async () => {
        barretenberg = await BarretenbergWasm.new();
        await barretenberg.init()
        pedersen = new SinglePedersen(barretenberg);
    });

    it("Should verify proof using abi for typescript", async function() {
        let preimage = [
            Buffer.from('0000000000000000000000000000000000000000000000000000000000000003', 'hex'), 
            Buffer.from('0000000000000000000000000000000000000000000000000000000000000004', 'hex'), 
            Buffer.from('0000000000000000000000000000000000000000000000000000000000005100', 'hex'), 
            Buffer.from('000000000000000000000000000000000000000000000000000000000000A200', 'hex'),
            Buffer.from('0000000000000000000000000000000000000000000000000000000000005100', 'hex'), 
        ];
        console.dir(preimage);
        // let salt = Buffer.from("0000000000000000000000000000000000000000000000000000000000000032", "hex"); // TODO: normally add salt but don't bother for now until pedersen working
        let solnHash = pedersen.compressInputs([...preimage]);
        let solnHashString = `0x` + solnHash.toString('hex');
        console.log('solnHash: ' + solnHashString); 

        let acirByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.acir'));
        let acir = acir_from_bytes(acirByteArray);

        let abi = {
            x: "0x03",
            y: "0x04",
            z: "0x5100",
            solnHash: solnHashString,
            return: ["0xA200", "0x5100"],
        }

        let [prover, verifier] = await setup_generic_prover_and_verifier(acir);
        console.log('created prover and verifier');
 
        const proof = await create_proof(prover, acir, abi);

        const verified = await verify_proof(verifier, proof);
      
        console.log(verified);

        expect(verified).eq(true)
    });

    // it("Should verify proof using witness arr", async function() {
    //     let acirByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.acir'));
    //     let acir = acir_from_bytes(acirByteArray);

    //     let witnessByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.tr'));
    //     const barretenberg_witness_arr = await packed_witness_to_witness(acir, witnessByteArray);

    //     let [prover, verifier] = await setup_generic_prover_and_verifier(acir);
    //     console.log('created prover and verifier');
    
    //     const proof = await create_proof_with_witness(prover, barretenberg_witness_arr);
    //     console.log('proof: ' + proof.toString('hex'));
    
    //     const verified = await verify_proof(verifier, proof);

    //     expect(verified).eq(true)
    // });

    // it("Should verify proof using compute witness", async function() {
    //     let acirByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.acir'));
    //     let acir = acir_from_bytes(acirByteArray);

    //     let [prover, verifier] = await setup_generic_prover_and_verifier(acir);
    //     console.log('created prover and verifier');
 
    //     let initial_js_witness = ["0x03", "0x04", "0x5100", "0xA200", "0x5100"];
    //     // NOTE: breaks without even number of bytes specified, the line below does not work
    //     // let initial_js_witness = ["0x3", "0x4", "0x5100"];

    //     let barretenberg_witness_arr = compute_witnesses(acir, initial_js_witness);
    //     console.log('barretenberg_witness_arr: ' + Buffer.from(barretenberg_witness_arr).toString('hex'));

    //     const proof = await create_proof_with_witness(prover, barretenberg_witness_arr);

    //     console.log('proof: ' + proof.toString('hex'));
    
    //     const verified = await verify_proof(verifier, proof);

    //     expect(verified).eq(true)
    // });

    // it("Should verify proof using abi for typescript", async function() {
    //     // let path = "../circuits/src/main.nr"

    //     // TODO: we can also parse the .toml file, instead of using the ABI
    //     // 2) Compile noir program

    //     // TODO: this breaks when main has a return, can remove return in the circuit and uncomment this to show compile working correctly 
    //     // const compiled_program = compile(path.resolve(__dirname, '../circuits/src/main.nr')); 
    //     // let acir = compiled_program.circuit;
    //     // const abi = compiled_program.abi;
    //     // console.dir(acir);

    //     let acirByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.acir'));
    //     let acir = acir_from_bytes(acirByteArray);

    //     let abi = {
    //         x: "0x03",
    //         y: "0x04",
    //         z: "0x5100",
    //         return: ["0xA200", "0x5100"],
    //     }

    //     let [prover, verifier] = await setup_generic_prover_and_verifier(acir);
    //     console.log('created prover and verifier');
 
    //     const proof = await create_proof(prover, acir, abi);

    //     const verified = await verify_proof(verifier, proof);
      
    //     console.log(verified);

    //     expect(verified).eq(true)
    // });

});

describe('1_mul using solidity verifier', function() {
    let Verifier: ContractFactory;
    let verifierContract: Contract;

    before(async () => {
        Verifier = await ethers.getContractFactory("TurboVerifier");
        verifierContract = await Verifier.deploy();
    });

    it("Should verify using proof generated by nargo", async () => {
        // NOTE: this reads from the proof generated by nargo prove, and buffer doesn't give accurate binary data on its own needs to be converted
        // Also, the proof is not pre-pended with public inputs unlike in Noir/barretenberg, thus we don't need to prepend them for the generated Sol verifier
        let proofBuffer = readFileSync(path.resolve(__dirname,`../circuits/proofs/p.proof`));
        console.log('proofBuffer: ', proofBuffer.toString());

        const proof = hexToBytes(proofBuffer.toString());
        console.log('proof: ', proof);

        let public_inputs_hex = [
            "0x0000000000000000000000000000000000000000000000000000000000000004",
            "0x0000000000000000000000000000000000000000000000000000000000005100",
            "0x000000000000000000000000000000000000000000000000000000000000A200",
            "0x0000000000000000000000000000000000000000000000000000000000005100",
        ]
        let pubInputsByteArray = hexListToBytes(public_inputs_hex);
        console.log('public_inputs_hex: ', pubInputsByteArray);
        
        const verifyResult = await verifierContract.verify(proof, pubInputsByteArray);
        console.log('verify result: ' + verifyResult);

        expect(verifyResult).eq(true)
    });

    // TODO: test is currently broken, need to add ability to generate the verifier contract using the updated typescript wrapper
    // it("Should verify using proof generated by typescript wrapper", async () => {
    //     const numPublicInputs = 4;
    //     let acirByteArray = path_to_uint8array(path.resolve(__dirname, '../circuits/build/p.acir'));
    //     let acir = acir_from_bytes(acirByteArray);

    //     let abi = {
    //         x: "0x03",
    //         y: "0x04",
    //         z: "0x5100",
    //         return: ["0xA200", "0x5100"],
    //     }
    //     console.dir(abi)

    //     let [prover, verifier] = await setup_generic_prover_and_verifier(acir);
    //     console.log('created prover and verifier');
 
    //     const proof: Buffer = await create_proof(prover, acir, abi);
    //     const publicInputs: Buffer = proof.subarray(0, (numPublicInputs*32));
    //     console.log('proof: ' + proof.toString('hex'));
    //     const verified = await verify_proof(verifier, proof);
    //     console.log(verified);

    //     // TODO: currently broken, getting malformed G1 point, check if verifier contract generated by nargo has mismatch with proof generated by JS wrapper
    //     let proofNoPubInputs = proof.subarray(numPublicInputs*32);
    //     console.log('public inputs: ', publicInputs.toString('hex'));
    //     console.log('proof no pub inputs: ' + proofNoPubInputs.toString('hex'));
    //     const verifyResult = await verifierContract.verify(proofNoPubInputs, publicInputs);
    //     console.log('verify result: ' + verifyResult);

    //     expect(verified).eq(true)
    // });

});

function path_to_uint8array(path: string) {
    let buffer = readFileSync(path);
    return new Uint8Array(buffer);
}

function hexListToBytes(list: string[]) {
    let rawPubInputs = [];
    for (let i = 0; i < list.length; i++) {
      let rawPubInput = utils.arrayify(list[i]);
      rawPubInputs.push(rawPubInput)
    }
    // Get the total length of all arrays.
    let length = 0;
    rawPubInputs.forEach(item => {
      length += item.length;
    });
  
    // Create a new array with total length and merge all source arrays.
    let mergedRawPubInputs = new Uint8Array(length);
    let offset = 0;
    rawPubInputs.forEach(item => {
      mergedRawPubInputs.set(item, offset);
      offset += item.length;
    });
    return mergedRawPubInputs
}

// Convert a hex string to a byte array
function hexToBytes(hex: string) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}
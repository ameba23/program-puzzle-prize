<!-- Generated with cargo generate entropyxyz/programs -->

# program-puzzle-prize

This is an [entropy](https://entropy.xyz) [program](https://github.com/entropyxyz/programs) inspired by the famous bitcoin puzzle painting ['TORCHED H34R7S'](https://www.vice.com/en/article/kzpqzz/heres-the-solution-to-the-3-year-old-dollar50000-bitcoin-puzzle)

![TORCHED H34R7S](https://video-images.vice.com/articles/5a751340f9fa9a4fe5250b5f/lede/1517622121322-1FLAMEN6.jpeg?crop=1xw:0.75xh;center,center&resize=500:*)

The program configuration contains a string description of the puzzle to be solved, eg: 'What is the meaning of life?'. This could also be a URL to some more elaborate puzzle.

The program configuration also contains some data encrypted using the hash of the puzzle's solution as the encryption key.

The account deployer may fund the account with some crypto asset prize of their choosing.

Anybody can attempt to solve the puzzle by submitting a transaction request with their proposed solution, eg: '42', in the program's auxiliary data.

The program will hash the solution and attempt to decrypt the ciphertext from the program configuration with it. If successful, the message provided by the user will be signed, potentially moving the crypto asset prize. 

## Running tests

`cargo test`

## Building the program

Get the necessary build tools with:

```shell
cargo install cargo-component --version 0.2.0 &&
cargo install wasm-tools
```

Then build with:

```shell
cargo component build --release --target wasm32-unknown-unknown
```

The `.wasm` binary can be found in `./target/wasm32-unknown-unknown/release`

## Building with docker

If you want to make your program publicly available and open source, and make it possible for others to verify that the source code corresponds to the on-chain binary, you can build it with the included Dockerfile:

```shell
docker build --output=binary-dir .
```

This will compile your program and put the `.wasm` binary file in `./binary-dir`.

## Generate Types

Types are meant top be posted with the program, it is how people know how to interact with your program

They will be autogenerated when running store-programs, or you can run it manually

```shell
cargo run -p cli generate-types
```

Will generate two files that will hold both the aux_data_schema and config_schema

## Upload program

The basic template is shipped with a cli to upload a program, after compiling the program then generating the types
you upload the program to chain.

Create a .env file with two variables

```env
DEPLOYER_MNEMONIC="<Your Deployer Mnemonic>"
CHAIN_ENDPOINT="<Chain Endpoint>"
```

Then run:

```shell
cargo run -p cli store-program
```

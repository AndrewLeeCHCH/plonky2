use log::{Level, LevelFilter};
use merkle_stark::{
    config::StarkConfig,
    prover::prove,
    sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor},
    verifier::verify_stark_proof,
};
use plonky2::{hash::hash_types::BytesHash, timed};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use merkle_stark::serialization::Buffer;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

const NUM_HASHES: usize = 1024;

fn main() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    let mut compressor = Sha2StarkCompressor::new();
    let mut trace;

    let mut timing = TimingTree::new("generate pw", Level::Info);
    timed!(timing, "witness generation", {
        for _ in 0..NUM_HASHES {
            let left = BytesHash::<32>::rand().0;
            let right = BytesHash::<32>::rand().0;
    
            compressor.add_instance(left, right);
        }
    
        trace = compressor.generate();
    });
    timing.print();

    let mut config1 = StarkConfig::standard_fast_config();
    config1.fri_config.proof_of_work_bits = 18;
    config1.fri_config.rate_bits = 1;
    config1.fri_config.num_query_rounds = 82;

    let mut config2 = StarkConfig::standard_fast_config();
    config2.fri_config.proof_of_work_bits = 18;
    config2.fri_config.rate_bits = 2;
    config2.fri_config.num_query_rounds = 41;

    let mut config3 = StarkConfig::standard_fast_config();
    config3.fri_config.proof_of_work_bits = 18;
    config3.fri_config.rate_bits = 3;
    config3.fri_config.num_query_rounds = 28;

    let mut config4 = StarkConfig::standard_fast_config();
    config4.fri_config.proof_of_work_bits = 18;
    config4.fri_config.rate_bits = 4;
    config4.fri_config.num_query_rounds = 21;

    let config = config1;

    let stark = S::new();
    let mut timing = TimingTree::new("prove", Level::Info);
    let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing).unwrap();
    timing.print();
    let mut buffer = Buffer::new(Vec::new());
    buffer.write_stark_proof_with_public_inputs(&proof).unwrap();
    println!("proof size {}", buffer.bytes().len());

    let timing = TimingTree::new("verify", Level::Info);
    verify_stark_proof(stark, proof, &config).unwrap();
    timing.print();
}

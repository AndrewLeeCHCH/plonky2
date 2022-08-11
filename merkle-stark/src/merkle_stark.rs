use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::config::StarkConfig;
use crate::cross_table_lookup::{CrossTableLookup, TableWithColumns};
use crate::sha256_stark::{self, Sha2CompressionStark};
use crate::tree_stark::{self, MerkleTree5STARK};
use crate::stark::Stark;

#[derive(Clone)]
pub struct Merkle5STARK<F: RichField + Extendable<D>, const D: usize> {
    pub hash_stark: Sha2CompressionStark<F, D>,
    pub tree_stark: MerkleTree5STARK<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for Merkle5STARK<F, D> {
    fn default() -> Self {
        Self {
            hash_stark: Sha2CompressionStark::default(),
            tree_stark: MerkleTree5STARK::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Merkle5STARK<F, D> {
    pub(crate) fn nums_permutation_zs(&self, config: &StarkConfig) -> Vec<usize> {
        let ans = vec![
            self.hash_stark.num_permutation_batches(config),
            self.tree_stark.num_permutation_batches(config),
        ];
        debug_assert_eq!(ans.len(), Table::num_tables());
        ans
    }

    pub(crate) fn permutation_batch_sizes(&self) -> Vec<usize> {
        let ans = vec![
            self.hash_stark.permutation_batch_size(),
            self.tree_stark.permutation_batch_size(),
        ];
        debug_assert_eq!(ans.len(), Table::num_tables());
        ans
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Table {
    Hash = 0,
    Tree = 1,
}

impl Table {
    pub(crate) fn num_tables() -> usize {
        Table::Tree as usize + 1
    }
}

#[allow(unused)] // TODO: Should be used soon.
pub(crate) fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    let mut cross_table_lookups = vec![ctl_hash(), ctl_tree()];
    cross_table_lookups
}

fn ctl_hash<F: Field>() -> CrossTableLookup<F> {
    CrossTableLookup::new(
        vec![TableWithColumns::new(
            Table::Tree,
            tree_stark::ctl_data_hash(),
            Some(tree_stark::ctl_filter_hash()),
        )],
        TableWithColumns::new(
            Table::Hash,
            sha256_stark::ctl_data(),
            Some(sha256_stark::ctl_filter()),
        ),
        None,
    )
}

fn ctl_tree<F: Field>() -> CrossTableLookup<F> {
    CrossTableLookup::new(
        vec![TableWithColumns::new(
            Table::Hash,
            sha256_stark::ctl_data_tree(),
            Some(sha256_stark::ctl_filter_tree()),
        )],
        TableWithColumns::new(Table::Tree, tree_stark::ctl_data(), Some(tree_stark::ctl_filter())),
        None,
    )
}


#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use plonky2_util::log2_ceil;
    use rand::{thread_rng, Rng};

    use crate::merkle_stark::Merkle5STARK;
    use crate::tree_stark::{MerkleTree5STARK, layout::{TREE_WIDTH, level_width}, generation::TreeTraceGenerator};
    use crate::sha256_stark::{Sha2CompressionStark, generation::Sha2TraceGenerator};
    use crate::config::StarkConfig;
    use crate::cross_table_lookup::testutils::check_ctls;
    use crate::proof::Merkle5STARKProof;
    use crate::prover::prove;
    use crate::recursive_verifier::{
        add_virtual_merkle_5_proof, set_merkle_5_proof_target, verify_proof_circuit,
    };
    use crate::stark::Stark;
    use crate::verifier::verify_proof;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    const NUM_HASHES: usize = 15;


    fn make_tree_trace(
        tree_stark: &MerkleTree5STARK<F, D>,
        leaves: [[u32; 8]; TREE_WIDTH]
    ) -> Vec<PolynomialValues<F>> {
        let mut generator = TreeTraceGenerator::new(NUM_HASHES + 1, leaves);
        generator.gen();
        generator.into_polynomial_values()
    }

    fn gen_merkle_root(generator: &mut Sha2TraceGenerator<F>, mut leaves: [[u32; 8]; TREE_WIDTH]) -> [u32; 8] {
        for level in 1..5 {
            for i in (0..level_width(level)).step_by(2) {
                leaves[i] = generator.gen_hash(leaves[i], leaves[i + 1]);
            }
        }

        leaves[0]
    }

    fn make_hash_trace(
        hash_stark: &Sha2CompressionStark<F, D>,
        leaves: [[u32; 8]; TREE_WIDTH]
    ) -> ([u32; 8], Vec<PolynomialValues<F>>) {
        let num_rows = 1 << log2_ceil(NUM_HASHES);
        let mut generator = Sha2TraceGenerator::new(num_rows);
        let root = gen_merkle_root(&mut generator, leaves);

        (root, generator.into_polynomial_values())
    }
    
    fn get_proof(config: &StarkConfig) -> Result<(Merkle5STARK<F, D>, Merkle5STARKProof<F, C, D>)> {
        let merkle_5_stark = Merkle5STARK::default();

        let num_logic_rows = 62;
        let num_memory_ops = 1 << 5;

        let mut rng = thread_rng();
        let num_keccak_perms = 2;

        let leaves: [[u32; 8]; TREE_WIDTH] = [(); TREE_WIDTH].map(|_| [(); 8].map(|_| rng.gen()));

        let tree_trace = make_tree_trace(&merkle_5_stark.tree_stark, leaves);
        let (root, hash_trace) = make_hash_trace(&merkle_5_stark.hash_stark, leaves);

        let traces = vec![tree_trace, hash_trace];
        check_ctls(&traces, &merkle_5_stark.cross_table_lookups);

        let proof = prove::<F, C, D>(
            &merkle_5_stark,
            config,
            traces,
            vec![vec![]; 4],
            &mut TimingTree::default(),
        )?;

        Ok((merkle_5_stark, proof))
    }

    #[test]
    fn test_merkle_5_stark() -> Result<()> {
        let config = StarkConfig::standard_fast_config();
        let (merkle_5_stark, proof) = get_proof(&config)?;
        verify_proof(merkle_5_stark, proof, &config)
    }

    #[test]
    fn test_merkle_5_stark_recursive_verifier() -> Result<()> {
        init_logger();

        let config = StarkConfig::standard_fast_config();
        let (merkle_5_stark, proof) = get_proof(&config)?;
        verify_proof(merkle_5_stark.clone(), proof.clone(), &config)?;

        recursive_proof(merkle_5_stark, proof, &config, true)
    }

    fn recursive_proof(
        inner_merkle_5_stark: Merkle5STARK<F, D>,
        inner_proof: Merkle5STARKProof<F, C, D>,
        inner_config: &StarkConfig,
        print_gate_counts: bool,
    ) -> Result<()> {
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let mut pw = PartialWitness::new();
        let degree_bits = inner_proof.degree_bits(inner_config);
        let nums_ctl_zs = inner_proof.nums_ctl_zs();
        let pt = add_virtual_merkle_5_proof(
            &mut builder,
            &inner_merkle_5_stark,
            inner_config,
            &degree_bits,
            &nums_ctl_zs,
        );
        set_merkle_5_proof_target(&mut pw, &pt, &inner_proof, builder.zero());

        verify_proof_circuit::<F, C, D>(&mut builder, inner_merkle_5_stark, pt, inner_config);

        if print_gate_counts {
            builder.print_gate_counts(0);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    fn init_logger() {
        let _ = env_logger::builder().format_timestamp(None).try_init();
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// returns (x, y, circuit)
    /// not-too-simple test circuit representing the following:
    /// y = (x == a) ? f(x) : g(x)
    /// f(x) = x^2 + x + 1
    /// g(x) = 6x^2 + 2x + 3
    /// where a is a constant
    fn example_circuit_0(a: u32) -> (Target, Target, CircuitData<F, C, D>) {
        // start with the standard cirucit config. It's probably way larger than necessary
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        builder.register_public_input(x);

        // f(x)
        let x_squared_plus_x = builder.arithmetic(1u32.into(), 1u32.into(), x, x, x);
        let f_x = builder.add_const(x_squared_plus_x, 1u32.into());

        // g(x)
        let six_x_squared_plus_two_x = builder.arithmetic(6u32.into(), 2u32.into(), x, x, x);
        let g_x = builder.add_const(six_x_squared_plus_two_x, 3u32.into());

        // x == a

        let _a = builder.constant(a.into());
        let x_minus_a = builder.sub(x, _a);
        // comparison works on lower-radix number systems. Gate degree for the splitter is the limb base,
        // so choose binary because it gives the smallest degree.
        // convert to binary by splitting x_minus_a into 64 base-2 limbs
        let x_minus_a_split = builder.split_le_base::<2>(x_minus_a, 64);
        let zero = builder.zero();
        let x_eq_a = builder.list_le(x_minus_a_split, vec![zero; 64], 1);

        // select f_x or g_x based on x_eq_a
        let y = builder.select(x_eq_a, f_x, g_x);
        builder.register_public_input(y);

        (x, y, builder.build::<C>())
    }

    #[test]
    #[ignore]
    fn example_nonrecursive_0() -> Result<()> {
        // build the circuit (see above)
        let (x, y, circuit) = example_circuit_0(42);

        // set the public inputs via a PartialWitness
        // set x = 42. Then x == 0, so y should be f(x) = 1807
        let mut pw = PartialWitness::new();
        pw.set_target(x, 42u32.into());
        pw.set_target(y, 1807u32.into());

        // prove
        let proof = circuit.prove(pw)?;

        // verify
        circuit.verify(proof).expect("expected verifier to accept");

        // make another proof with different inputs.
        // this time, x = 420 => y should be g(x) = 1059243
        let mut pw = PartialWitness::new();
        pw.set_target(x, 420u32.into());
        pw.set_target(y, 1059243u32.into());

        let proof = circuit.prove(pw)?;
        circuit.verify(proof).expect("expected verifier to accept");

        Ok(())
    }

    #[test]
    #[ignore]
    #[should_panic]
    fn example_nonrecursive_0_construct_invalid_proof() {
        let (x, y, circuit) = example_circuit_0(6);

        // set x = 21. 21 != 6, so y should be g(x) = 2691, but set it to f(x) = 463 instead.
        let mut pw = PartialWitness::new();
        pw.set_target(x, 21u32.into());
        pw.set_target(y, 463u32.into());
        let _proof_should_panic = circuit.prove(pw);
    }
}

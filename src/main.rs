use std::path::Path;

use shuffle_api::ShuffleChip;
use sirius::{
    ff::Field,
    halo2_proofs::circuit::Value,
    ivc::{
        step_circuit::{trivial, AssignedCell, ConstraintSystem, Layouter},
        SynthesisError,
    },
    prelude::{
        bn256::{new_default_pp, C1Affine, C1Scalar, C2Affine, C2Scalar},
        CommitmentKey, PrimeField, StepCircuit, IVC,
    },
};

#[allow(dead_code)]
mod shuffle_api;

/// Number of folding steps
const FOLD_STEP_COUNT: usize = 5;

// === PRIMARY ===

/// Arity : Input/output size per fold-step for primary step-circuit
const A1: usize = 1;

/// Input to be passed on the zero step to the primary circuit
const PRIMARY_Z_0: [C1Scalar; A1] = [C1Scalar::ZERO];

/// Key size for Primary Circuit
///
/// This is the minimum value, for your circuit you may get the output that the key size is
/// insufficient, then increase this constant
const PRIMARY_COMMITMENT_KEY_SIZE: usize = 20;

/// Table size for Primary Circuit
///
/// Requires at least 17, for service purposes, but if the primary requires more, increase the
/// constant
const PRIMARY_CIRCUIT_TABLE_SIZE: usize = 17;

// === SECONDARY ===

/// Arity : Input/output size per fold-step for secondary step-circuit
/// For tivial case it can be any number
const A2: usize = 1;

/// Input to be passed on the zero step to the secondary circuit
const SECONDARY_Z_0: [C2Scalar; A1] = [C2Scalar::ZERO];

/// Table size for Primary Circuit
///
/// Requires at least 17, for service purposes, but if the primary requires more, increase the
/// constant
const SECONDARY_CIRCUIT_TABLE_SIZE: usize = 17;

/// Key size for Secondary Circuit
///
/// This is the minimum value, for your circuit you may get the output that the key size is
/// insufficient, then increase this constant
const SECONDARY_COMMITMENT_KEY_SIZE: usize = 20;

/// This structure is a template for configuring your circuit
///
/// It should store information about your PLONKish structure
#[derive(Debug, Clone)]
struct MyStepCircuit<const L: usize, F: PrimeField> {
    input_0: Vec<Value<F>>,
    input_1: Vec<F>,
    shuffle_0: Vec<Value<F>>,
    shuffle_1: Vec<Value<F>>,
}

type MyConfig = shuffle_api::ShuffleConfig;

impl<const A: usize, F: PrimeField> StepCircuit<A, F> for MyStepCircuit<A, F> {
    /// This is a configuration object that stores things like columns.
    type Config = MyConfig;

    /// Configure the step circuit. This method initializes necessary
    /// fixed columns and advice columns, but does not create any instance
    /// columns.
    ///
    // TODO #329
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let input_0 = meta.advice_column();
        let input_1 = meta.fixed_column();
        let shuffle_0 = meta.advice_column();
        let shuffle_1 = meta.advice_column();
        ShuffleChip::configure(meta, input_0, input_1, shuffle_0, shuffle_1)
    }

    /// Sythesize the circuit for a computation step and return variable
    /// that corresponds to the output of the step z_{i+1}
    /// this method will be called when we synthesize the IVC_Circuit
    ///
    /// Return `z_out` result
    fn synthesize_step(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
        _z_i: &[AssignedCell<F, F>; A],
    ) -> Result<[AssignedCell<F, F>; A], SynthesisError> {
        let ch = ShuffleChip::<F>::construct(config);

        layouter.assign_region(
            || "load inputs",
            |mut region| {
                for (i, (input_0, input_1)) in
                    self.input_0.iter().zip(self.input_1.iter()).enumerate()
                {
                    region.assign_advice(|| "input_0", ch.config.input_0, i, || *input_0)?;
                    region.assign_fixed(
                        || "input_1",
                        ch.config.input_1,
                        i,
                        || Value::known(*input_1),
                    )?;
                    ch.config.s_input.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "load shuffles",
            |mut region| {
                for (i, (shuffle_0, shuffle_1)) in
                    self.shuffle_0.iter().zip(self.shuffle_1.iter()).enumerate()
                {
                    region.assign_advice(|| "shuffle_0", ch.config.shuffle_0, i, || *shuffle_0)?;
                    region.assign_advice(|| "shuffle_1", ch.config.shuffle_1, i, || *shuffle_1)?;
                    ch.config.s_shuffle.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;

        todo!()
    }
}

fn main() {
    let input_0 = [1, 2, 4, 1]
        .map(|e: u64| Value::known(C1Scalar::from(e)))
        .to_vec();
    let input_1 = [10, 20, 40, 10].map(C1Scalar::from).to_vec();
    let shuffle_0 = [4, 1, 1, 2]
        .map(|e: u64| Value::known(C1Scalar::from(e)))
        .to_vec();
    let shuffle_1 = [40, 10, 10, 20]
        .map(|e: u64| Value::known(C1Scalar::from(e)))
        .to_vec();

    let sc1 = MyStepCircuit::<A1, C1Scalar> {
        input_0,
        input_1,
        shuffle_0,
        shuffle_1,
    };

    let sc2 = trivial::Circuit::<A2, C2Scalar>::default();

    // This folder will store the commitment key so that we don't have to generate it every time.
    //
    // NOTE: since the key files are not serialized, but reflected directly from memory, the
    // functions to load them is `unsafe`
    let key_cache = Path::new(".cache");

    println!("start setup primary commitment key: bn256");

    // Safety: because the cache file is correct
    let primary_commitment_key = unsafe {
        CommitmentKey::<C1Affine>::load_or_setup_cache(
            key_cache,
            "bn256",
            PRIMARY_COMMITMENT_KEY_SIZE,
        )
        .unwrap()
    };

    println!("start setup secondary commitment key: grumpkin");

    // Safety: because the cache file is correct
    let secondary_commitment_key = unsafe {
        CommitmentKey::<C2Affine>::load_or_setup_cache(
            key_cache,
            "grumpkin",
            SECONDARY_COMMITMENT_KEY_SIZE,
        )
        .unwrap()
    };

    let pp = new_default_pp::<A1, _, A2, _>(
        SECONDARY_CIRCUIT_TABLE_SIZE as u32,
        &primary_commitment_key,
        &sc1,
        PRIMARY_CIRCUIT_TABLE_SIZE as u32,
        &secondary_commitment_key,
        &sc2,
    );

    let mut ivc = IVC::new(&pp, &sc1, PRIMARY_Z_0, &sc2, SECONDARY_Z_0, true)
        .expect("failed to create `IVC`");
    println!("ivc created");

    for step in 1..FOLD_STEP_COUNT {
        // you can modify circuit data here
        ivc.fold_step(&pp, &sc1, &sc2)
            .expect("failed to run fold step");

        println!("folding step {step} was successful");
    }

    ivc.verify(&pp).expect("failed to verify ivc");
    println!("verification successful");

    println!("success");
}

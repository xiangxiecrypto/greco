use crate::constants::sk_enc_constants_4096_2x55_65537::{
    E_BOUND, K0IS, K1_BOUND, N, QIS, R1_BOUNDS, R2_BOUNDS, S_BOUND,
};

use axiom_eth::rlc::{
    chip::RlcChip,
    circuit::{builder::RlcCircuitBuilder, instructions::RlcCircuitInstructions, RlcCircuitParams},
};
use halo2_base::{
    gates::{circuit::BaseCircuitParams, GateInstructions, RangeChip, RangeInstructions},
    utils::ScalarField,
    QuantumCell::Constant,
};

use serde::Deserialize;

use crate::poly::{Poly, PolyAssigned};

/// Helper function to define the parameters of the RlcCircuit. This is a non-optimized configuration that makes use of a single advice column. Use this for testing purposes only.
fn re_enc_test_params() -> RlcCircuitParams {
    RlcCircuitParams {
        base: BaseCircuitParams {
            k: 21,
            num_advice_per_phase: vec![1, 1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![0, 1],
            lookup_bits: Some(8),
            num_instance_columns: 0,
        },
        num_rlc_columns: 1,
    }
}

/// `BfvSkReEncryptionCircuit` is a circuit that checks the correct formation of a ciphertext resulting from BFV secret key encryption
/// All the polynomials coefficients and scalars are normalized to be in the range `[0, p)` where p is the modulus of the prime field of the circuit
///
/// # Parameters:
/// * `s`: secret polynomial, sampled from ternary distribution.
/// * `e`: error polynomial, sampled from discrete Gaussian distribution.
/// * `k1`: scaled message polynomial.
/// * `r2is`: list of r2i polynomials for each i-th CRT basis .
/// * `r1is`: list of r1i polynomials for each CRT i-th CRT basis.
/// * `ais`: list of ai polynomials for each CRT i-th CRT basis.
/// * `ct0is`: list of ct0i (first component of the ciphertext cti) polynomials for each CRT i-th CRT basis.
#[derive(Deserialize, Clone)]
pub struct BfvSkReEncryptionCircuit {
    s_pre: Vec<String>,
    e_pre: Vec<String>,
    r2is_pre: Vec<Vec<String>>,
    r1is_pre: Vec<Vec<String>>,
    ais_pre: Vec<Vec<String>>,
    ct0is_pre: Vec<Vec<String>>,
    s: Vec<String>,
    e: Vec<String>,
    k1: Vec<String>,
    r2is: Vec<Vec<String>>,
    r1is: Vec<Vec<String>>,
    ais: Vec<Vec<String>>,
    ct0is: Vec<Vec<String>>,
}
impl BfvSkReEncryptionCircuit {
    fn params_test(&self) {
        assert_eq!(self.ais_pre, self.ais);
        assert_eq!(self.s_pre, self.s);
        assert_eq!(self.r2is_pre, self.r2is);
        assert_eq!(self.r1is_pre, self.r1is);
        assert_eq!(self.e_pre, self.e);
        assert_eq!(self.ct0is_pre, self.ct0is);
    }
}

/// Payload returned by the first phase of the circuit to be reused in the second phase
pub struct Payload<F: ScalarField> {
    s_pre_assigned: PolyAssigned<F>,
    e_pre_assigned: PolyAssigned<F>,
    r2is_pre_assigned: Vec<PolyAssigned<F>>,
    r1is_pre_assigned: Vec<PolyAssigned<F>>,
    ais_pre: Vec<Vec<String>>,
    ct0is_pre: Vec<Vec<String>>,
    s_assigned: PolyAssigned<F>,
    e_assigned: PolyAssigned<F>,
    k1_assigned: PolyAssigned<F>,
    r2is_assigned: Vec<PolyAssigned<F>>,
    r1is_assigned: Vec<PolyAssigned<F>>,
    ais: Vec<Vec<String>>,
    ct0is: Vec<Vec<String>>,
}

impl<F: ScalarField> RlcCircuitInstructions<F> for BfvSkReEncryptionCircuit {
    type FirstPhasePayload = Payload<F>;

    fn virtual_assign_phase0(
        &self,
        builder: &mut RlcCircuitBuilder<F>,
        _: &RangeChip<F>,
    ) -> Self::FirstPhasePayload {
        let ctx = builder.base.main(0);

        let s_pre = Poly::<F>::new(self.s_pre.clone());
        let s_pre_assigned = PolyAssigned::new(ctx, s_pre);

        let e_pre = Poly::<F>::new(self.e_pre.clone());
        let e_pre_assigned = PolyAssigned::new(ctx, e_pre);

        let mut r2is_pre_assigned = vec![];
        let mut r1is_pre_assigned = vec![];

        for z in 0..self.ct0is_pre.len() {
            let r2i_pre = Poly::<F>::new(self.r2is_pre[z].clone());
            let r2i_pre_assigned = PolyAssigned::new(ctx, r2i_pre);
            r2is_pre_assigned.push(r2i_pre_assigned);

            let r1i_pre = Poly::<F>::new(self.r1is_pre[z].clone());
            let r1i_pre_assigned = PolyAssigned::new(ctx, r1i_pre);
            r1is_pre_assigned.push(r1i_pre_assigned);
        }

        let s = Poly::<F>::new(self.s.clone());
        let s_assigned = PolyAssigned::new(ctx, s);

        let e = Poly::<F>::new(self.e.clone());
        let e_assigned = PolyAssigned::new(ctx, e);

        let k1 = Poly::<F>::new(self.k1.clone());
        let k1_assigned = PolyAssigned::new(ctx, k1);

        let mut r2is_assigned = vec![];
        let mut r1is_assigned = vec![];

        for z in 0..self.ct0is.len() {
            let r2i = Poly::<F>::new(self.r2is[z].clone());
            let r2i_assigned = PolyAssigned::new(ctx, r2i);
            r2is_assigned.push(r2i_assigned);

            let r1i = Poly::<F>::new(self.r1is[z].clone());
            let r1i_assigned = PolyAssigned::new(ctx, r1i);
            r1is_assigned.push(r1i_assigned);
        }
        Payload {
            s_pre_assigned,
            e_pre_assigned,
            r2is_pre_assigned,
            r1is_pre_assigned,
            ais_pre: self.ais_pre.clone(),
            ct0is_pre: self.ct0is_pre.clone(),
            s_assigned,
            e_assigned,
            k1_assigned,
            r2is_assigned,
            r1is_assigned,
            ais: self.ais.clone(),
            ct0is: self.ais.clone(),
        }
    }

    fn virtual_assign_phase1(
        builder: &mut RlcCircuitBuilder<F>,
        range: &RangeChip<F>,
        rlc: &RlcChip<F>,
        payload: Self::FirstPhasePayload,
    ) {
        let Payload {
            s_pre_assigned,
            e_pre_assigned,
            r2is_pre_assigned,
            r1is_pre_assigned,
            ais_pre,
            ct0is_pre,
            s_assigned,
            e_assigned,
            k1_assigned,
            r2is_assigned,
            r1is_assigned,
            ais,
            ct0is,
        } = payload;

        let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();
        let gamma = *rlc.gamma();

        let mut ais_pre_at_gamma_assigned = vec![];
        let mut ct0is_pre_at_gamma_assigned = vec![];
        let mut qi_constants = vec![];
        let mut k0i_constants = vec![];

        for z in 0..ct0is_pre.len() {
            let ai_pre = Poly::<F>::new(ais_pre[z].clone());
            let ai_pre_at_gamma = ai_pre.eval(gamma);
            let ai_pre_at_gamma_assigned = ctx_gate.load_witness(ai_pre_at_gamma);
            ais_pre_at_gamma_assigned.push(ai_pre_at_gamma_assigned);

            let ct0i_pre = Poly::<F>::new(ct0is_pre[z].clone());
            let ct0i_pre_at_gamma = ct0i_pre.eval(gamma);
            let ct0i_pre_at_gamma_assigned = ctx_gate.load_witness(ct0i_pre_at_gamma);
            ct0is_pre_at_gamma_assigned.push(ct0i_pre_at_gamma_assigned);

            let qi_constant = Constant(F::from_str_vartime(QIS[z]).unwrap());
            qi_constants.push(qi_constant);

            let k0i_constant = Constant(F::from_str_vartime(K0IS[z]).unwrap());
            k0i_constants.push(k0i_constant);
        }

        // cyclo poly is equal to x^N + 1
        let cyclo_at_gamma = gamma.pow_vartime([N as u64]) + F::from(1);
        let cyclo_at_gamma_assigned = ctx_gate.load_witness(cyclo_at_gamma);

        // RANGE CHECK
        s_pre_assigned.range_check(ctx_gate, range, S_BOUND);
        e_pre_assigned.range_check(ctx_gate, range, E_BOUND);
        k1_assigned.range_check(ctx_gate, range, K1_BOUND);

        for z in 0..ct0is_pre.len() {
            r2is_pre_assigned[z].range_check(ctx_gate, range, R2_BOUNDS[z]);
            r1is_pre_assigned[z].range_check(ctx_gate, range, R1_BOUNDS[z]);
        }

        // EVALUATION AT GAMMA CONSTRAINT

        let s_pre_at_gamma = s_pre_assigned.enforce_eval_at_gamma(ctx_rlc, rlc);
        let e_pre_at_gamma = e_pre_assigned.enforce_eval_at_gamma(ctx_rlc, rlc);
        let k1_at_gamma = k1_assigned.enforce_eval_at_gamma(ctx_rlc, rlc);

        let gate = range.gate();

        // For each `i` Prove that LHS(gamma) = RHS(gamma)
        // LHS = ct0i(gamma)
        // RHS = ai(gamma) * s(gamma) + e(gamma) + k1(gamma) * k0i + r1i(gamma) * qi + r2i(gamma) * cyclo(gamma)
        for z in 0..ct0is_pre.len() {
            let r1i_pre_at_gamma = r1is_pre_assigned[z].enforce_eval_at_gamma(ctx_rlc, rlc);
            let r2i_pre_at_gamma = r2is_pre_assigned[z].enforce_eval_at_gamma(ctx_rlc, rlc);

            // CORRECT ENCRYPTION CONSTRAINT

            // rhs = ai(gamma) * s(gamma) + e(gamma)
            let rhs = gate.mul_add(
                ctx_gate,
                ais_pre_at_gamma_assigned[z],
                s_pre_at_gamma,
                e_pre_at_gamma,
            );

            // rhs = rhs + k1(gamma) * k0i
            let rhs = gate.mul_add(ctx_gate, k1_at_gamma, k0i_constants[z], rhs);

            // rhs = rhs + r1i(gamma) * qi
            let rhs = gate.mul_add(ctx_gate, r1i_pre_at_gamma, qi_constants[z], rhs);

            // rhs = rhs + r2i(gamma) * cyclo(gamma)
            let rhs = gate.mul_add(ctx_gate, r2i_pre_at_gamma, cyclo_at_gamma_assigned, rhs);
            let lhs = ct0is_pre_at_gamma_assigned[z];

            // LHS(gamma) = RHS(gamma)
            let res = gate.is_equal(ctx_gate, lhs, rhs);
            gate.assert_is_const(ctx_gate, &res, &F::from(1));
        }

        ///////
        let mut ais_at_gamma_assigned = vec![];
        let mut ct0is_at_gamma_assigned = vec![];

        for z in 0..ct0is.len() {
            let ai = Poly::<F>::new(ais[z].clone());
            let ai_at_gamma = ai.eval(gamma);
            let ai_at_gamma_assigned = ctx_gate.load_witness(ai_at_gamma);
            ais_at_gamma_assigned.push(ai_at_gamma_assigned);

            let ct0i = Poly::<F>::new(ct0is[z].clone());
            let ct0i_at_gamma = ct0i.eval(gamma);
            let ct0i_at_gamma_assigned = ctx_gate.load_witness(ct0i_at_gamma);
            ct0is_at_gamma_assigned.push(ct0i_at_gamma_assigned);
        }

        // RANGE CHECK
        s_assigned.range_check(ctx_gate, range, S_BOUND);
        e_assigned.range_check(ctx_gate, range, E_BOUND);

        for z in 0..ct0is.len() {
            r2is_assigned[z].range_check(ctx_gate, range, R2_BOUNDS[z]);
            r1is_assigned[z].range_check(ctx_gate, range, R1_BOUNDS[z]);
        }

        // EVALUATION AT GAMMA CONSTRAINT

        let s_at_gamma = s_assigned.enforce_eval_at_gamma(ctx_rlc, rlc);
        let e_at_gamma = e_assigned.enforce_eval_at_gamma(ctx_rlc, rlc);

        // For each `i` Prove that LHS(gamma) = RHS(gamma)
        // LHS = ct0i(gamma)
        // RHS = ai(gamma) * s(gamma) + e(gamma) + k1(gamma) * k0i + r1i(gamma) * qi + r2i(gamma) * cyclo(gamma)
        for z in 0..ct0is.len() {
            let r1i_at_gamma = r1is_assigned[z].enforce_eval_at_gamma(ctx_rlc, rlc);
            let r2i_at_gamma = r2is_assigned[z].enforce_eval_at_gamma(ctx_rlc, rlc);

            // CORRECT ENCRYPTION CONSTRAINT

            // rhs = ai(gamma) * s(gamma) + e(gamma)
            let rhs = gate.mul_add(ctx_gate, ais_at_gamma_assigned[z], s_at_gamma, e_at_gamma);

            // rhs = rhs + k1(gamma) * k0i
            let rhs = gate.mul_add(ctx_gate, k1_at_gamma, k0i_constants[z], rhs);

            // rhs = rhs + r1i(gamma) * qi
            let rhs = gate.mul_add(ctx_gate, r1i_at_gamma, qi_constants[z], rhs);

            // rhs = rhs + r2i(gamma) * cyclo(gamma)
            let rhs = gate.mul_add(ctx_gate, r2i_at_gamma, cyclo_at_gamma_assigned, rhs);
            let lhs = ct0is_at_gamma_assigned[z];

            // LHS(gamma) = RHS(gamma)
            let res = gate.is_equal(ctx_gate, lhs, rhs);
            gate.assert_is_const(ctx_gate, &res, &F::from(1));
        }
    }
}

#[cfg(test)]
mod test {

    use super::re_enc_test_params;
    use crate::{
        constants::sk_enc_constants_4096_2x55_65537::R1_BOUNDS,
        sk_re_encryption_circuit::BfvSkReEncryptionCircuit,
    };
    use axiom_eth::rlc::{circuit::builder::RlcCircuitBuilder, utils::executor::RlcExecutor};
    use halo2_base::{
        gates::circuit::CircuitBuilderStage,
        halo2_proofs::{
            dev::{FailureLocation, MockProver, VerifyFailure},
            halo2curves::bn256::Fr,
            plonk::{keygen_pk, keygen_vk, Any, SecondPhase},
        },
        utils::{
            fs::gen_srs,
            testing::{check_proof, gen_proof},
        },
    };
    use std::{fs::File, io::Read};
    #[test]
    pub fn test_sk_re_enc_valid() {
        // 1. Define the inputs of the circuit
        let file_path = "src/data/sk_re_enc_4096_2x55_65537.json";
        let mut file = File::open(file_path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let sk_re_enc_circuit = serde_json::from_str::<BfvSkReEncryptionCircuit>(&data).unwrap();

        sk_re_enc_circuit.params_test();

        // 2. Build the circuit for MockProver using the test parameters
        let rlc_circuit_params = re_enc_test_params();
        let mut mock_builder: RlcCircuitBuilder<Fr> =
            RlcCircuitBuilder::from_stage(CircuitBuilderStage::Mock, 0)
                .use_params(rlc_circuit_params.clone());
        mock_builder.base.set_lookup_bits(8);

        let rlc_circuit = RlcExecutor::new(mock_builder, sk_re_enc_circuit);

        // 3. Run the mock prover. The circuit should be satisfied
        MockProver::run(
            rlc_circuit_params.base.k.try_into().unwrap(),
            &rlc_circuit,
            vec![],
        )
        .unwrap()
        .assert_satisfied();
    }
}

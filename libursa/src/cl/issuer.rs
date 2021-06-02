use bn::BigNumber;
use cl::constants::*;
use cl::hash::get_hash_as_int;
use cl::helpers::*;
use cl::*;
use errors::prelude::*;
use pair::*;
use utils::commitment::get_pedersen_commitment;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::iter::FromIterator;

/// Trust source that provides credentials to prover.
pub struct Issuer {}

impl Issuer {
    /// Creates and returns credential schema entity builder.
    ///
    /// The purpose of credential schema builder is building of credential schema entity that
    /// represents credential schema attributes set.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let _credential_schema = credential_schema_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_schema_builder() -> UrsaCryptoResult<CredentialSchemaBuilder> {
        let res = CredentialSchemaBuilder::new()?;
        Ok(res)
    }

    pub fn new_non_credential_schema_builder() -> UrsaCryptoResult<NonCredentialSchemaBuilder> {
        NonCredentialSchemaBuilder::new()
    }

    /// Creates and returns credential definition (public and private keys, correctness proof) entities.
    ///
    /// # Arguments
    /// * `credential_schema` - Credential schema entity.
    /// * `support_revocation` - If true non revocation part of keys will be generated.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    /// ```
    pub fn new_credential_def(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        support_revocation: bool,
    ) -> UrsaCryptoResult<(
        CredentialPublicKey,
        CredentialPrivateKey,
        CredentialKeyCorrectnessProof,
    )> {
        trace!(
            "Issuer::new_credential_def: >>> credential_schema: {:?}, support_revocation: {:?}",
            credential_schema,
            support_revocation
        );

        let (p_pub_key, p_priv_key, p_key_meta) =
            Issuer::_new_credential_primary_keys(credential_schema, non_credential_schema)?;

        Issuer::_new_credential_def_with_keys(
            credential_schema,
            support_revocation,
            p_pub_key,
            p_priv_key,
            p_key_meta,
        )
    }

    /// Creates and returns credential definition (public and private keys, correctness proof) entities.
    ///
    /// Same as `new_credential_def` but allows to pass pre-generated safe prime numbers to
    /// speed up credential definition generation. Safe prime numbers can be pre-generated with
    /// `ursa::helpers::generate_safe_prime`.
    ///
    /// # Arguments
    /// * `credential_schema` - Credential schema entity.
    /// * `support_revocation` - If true non revocation part of keys will be generated.
    /// * `p_safe` - pre-generated safe prime number
    /// * `q_safe` - pre-generated safe prime number
    ///
    /// # Example
    /// ```
    /// use ursa::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    /// ```
    pub fn new_credential_def_with_primes(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        support_revocation: bool,
        p_safe: &BigNumber,
        q_safe: &BigNumber,
    ) -> UrsaCryptoResult<(
        CredentialPublicKey,
        CredentialPrivateKey,
        CredentialKeyCorrectnessProof,
    )> {
        trace!(
            "Issuer::new_credential_def_with_primes: >>> credential_schema: {:?}, support_revocation: {:?}",
            credential_schema,
            support_revocation
        );

        let (p_pub_key, p_priv_key, p_key_meta) = Issuer::_new_credential_primary_keys_with_primes(
            credential_schema,
            non_credential_schema,
            p_safe,
            q_safe,
        )?;

        Issuer::_new_credential_def_with_keys(
            credential_schema,
            support_revocation,
            p_pub_key,
            p_priv_key,
            p_key_meta,
        )
    }

    /// Creates and returns revocation registry definition (public and private keys, accumulator and tails generator) entities.
    ///
    /// # Arguments
    /// * `credential_pub_key` - Credential public key entity.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `issuance_by_default` - Type of issuance.
    ///   If true all indices are assumed to be issued and initial accumulator is calculated over all indices
    ///   If false nothing is issued initially accumulator is 1
    ///
    /// # Example
    /// ```
    /// use ursa::cl::issuer::Issuer;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (_cred_pub_key, _cred_priv_key, _cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let (_rev_key_pub, _rev_key_priv, _rev_reg, _rev_tails_generator) = Issuer::new_revocation_registry_def(&_cred_pub_key, 5, false).unwrap();
    /// ```
    pub fn new_revocation_registry_def(
        credential_pub_key: &CredentialPublicKey,
        max_cred_num: u32,
        issuance_by_default: bool,
    ) -> UrsaCryptoResult<(
        RevocationKeyPublic,
        RevocationKeyPrivate,
        RevocationRegistry,
        RevocationTailsGenerator,
    )> {
        trace!("Issuer::new_revocation_registry_def: >>> credential_pub_key: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               credential_pub_key, max_cred_num, issuance_by_default);

        let cred_rev_pub_key: &CredentialRevocationPublicKey =
            credential_pub_key.r_key.as_ref().ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    "There are not revocation keys in the credential public key.",
                )
            })?;

        let (rev_key_pub, rev_key_priv) =
            Issuer::_new_revocation_registry_keys(cred_rev_pub_key, max_cred_num)?;

        let rev_reg = Issuer::_new_revocation_registry(
            cred_rev_pub_key,
            &rev_key_priv,
            max_cred_num,
            issuance_by_default,
        )?;

        let rev_tails_generator = RevocationTailsGenerator::new(
            max_cred_num,
            rev_key_priv.gamma,
            cred_rev_pub_key.g_dash,
        );

        trace!("Issuer::new_revocation_registry_def: <<< rev_key_pub: {:?}, rev_key_priv: {:?}, rev_reg: {:?}, rev_tails_generator: {:?}",
               rev_key_pub, secret!(&rev_key_priv), rev_reg, rev_tails_generator);

        Ok((rev_key_pub, rev_key_priv, rev_reg, rev_tails_generator))
    }

    /// Creates and returns credential values entity builder.
    ///
    /// The purpose of credential values builder is building of credential values entity that
    /// represents credential attributes values map.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::issuer::Issuer;
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let _credential_values = credential_values_builder.finalize().unwrap();
    /// ```
    pub fn new_credential_values_builder() -> UrsaCryptoResult<CredentialValuesBuilder> {
        let res = CredentialValuesBuilder::new()?;
        Ok(res)
    }

    /// Signs credential values with primary keys only.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_credential_secrets` - Blinded credential secrets generated by Prover.
    /// * `blinded_credential_secrets_correctness_proof` - Blinded credential secrets correctness proof.
    /// * `credential_nonce` - Nonce used for verification of blinded_credential_secrets_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Credential values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::new_nonce;
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("sex").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (credential_pub_key, credential_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
    /// let credential_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    /// let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
    ///      Prover::blind_credential_secrets(&credential_pub_key, &cred_key_correctness_proof, &credential_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_credential_signature, _signature_correctness_proof) =
    ///     Issuer::sign_credential("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                             &blinded_credential_secrets,
    ///                             &blinded_credential_secrets_correctness_proof,
    ///                             &credential_nonce,
    ///                             &credential_issuance_nonce,
    ///                             &credential_values,
    ///                             &credential_pub_key,
    ///                             &credential_priv_key).unwrap();
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn sign_credential(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        credential_priv_key: &CredentialPrivateKey,
    ) -> UrsaCryptoResult<(CredentialSignature, SignatureCorrectnessProof)> {
        trace!(
            "Issuer::sign_credential: >>> prover_id: {:?}\n \
             blinded_credential_secrets: {:?}\n \
             blinded_credential_secrets_correctness_proof: {:?}\n \
             credential_nonce: {:?}\n \
             credential_issuance_nonce: {:?}\n \
             credential_values: {:?}\n \
             credential_pub_key: {:?}\n \
             credential_priv_key: {:?}",
            prover_id,
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            credential_issuance_nonce,
            secret!(credential_values),
            credential_pub_key,
            secret!(credential_priv_key)
        );

        Issuer::_check_blinded_credential_secrets_correctness_proof(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            &credential_pub_key.p_key,
        )?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, None)?;

        let (p_cred, q) = Issuer::_new_primary_credential(
            &cred_context,
            credential_pub_key,
            credential_priv_key,
            blinded_credential_secrets,
            credential_values,
        )?;

        let cred_signature = CredentialSignature {
            p_credential: p_cred,
            r_credential: None,
        };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(
            &credential_pub_key.p_key,
            &credential_priv_key.p_key,
            &cred_signature.p_credential,
            &q,
            credential_issuance_nonce,
        )?;

        trace!(
            "Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}",
            secret!(&cred_signature),
            signature_correctness_proof
        );

        Ok((cred_signature, signature_correctness_proof))
    }

    /// Signs credential values with both primary and revocation keys.
    ///
    /// # Arguments
    /// * `prover_id` - Prover identifier.
    /// * `blinded_credential_secrets` - Blinded credential secrets generated by Prover.
    /// * `blinded_credential_secrets_correctness_proof` - Blinded credential secrets correctness proof.
    /// * `credential_nonce` - Nonce used for verification of blinded_credential_secrets_correctness_proof.
    /// * `credential_issuance_nonce` - Nonce used for creation of signature_correctness_proof.
    /// * `credential_values` - Credential values to be signed.
    /// * `credential_pub_key` - Credential public key.
    /// * `credential_priv_key` - Credential private key.
    /// * `rev_idx` - User index in revocation accumulator. Required for non-revocation credential_signature part generation.
    /// * `max_cred_num` - Max credential number in generated registry.
    /// * `rev_reg` - Revocation registry.
    /// * `rev_key_priv` - Revocation registry private key.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::{new_nonce, SimpleTailsAccessor};
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        1,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                        &simple_tail_accessor).unwrap();
    /// ```
    pub fn sign_credential_with_revoc<RTA>(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        credential_priv_key: &CredentialPrivateKey,
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg: &mut RevocationRegistry,
        rev_key_priv: &RevocationKeyPrivate,
        rev_tails_accessor: &RTA,
    ) -> UrsaCryptoResult<(
        CredentialSignature,
        SignatureCorrectnessProof,
        Option<RevocationRegistryDelta>,
    )>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?},\
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, max_cred_num: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, secret!(credential_values), credential_issuance_nonce,
               credential_pub_key, secret!(credential_priv_key), secret!(rev_idx), max_cred_num, rev_reg, secret!(rev_key_priv));

        Issuer::_check_blinded_credential_secrets_correctness_proof(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            &credential_pub_key.p_key,
        )?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, Some(rev_idx))?;

        let (p_cred, q) = Issuer::_new_primary_credential(
            &cred_context,
            credential_pub_key,
            credential_priv_key,
            blinded_credential_secrets,
            credential_values,
        )?;

        let (r_cred, rev_reg_delta) = Issuer::_new_non_revocation_credential(
            rev_idx,
            &cred_context,
            blinded_credential_secrets,
            credential_pub_key,
            credential_priv_key,
            max_cred_num,
            issuance_by_default,
            rev_reg,
            rev_key_priv,
            rev_tails_accessor,
        )?;

        let cred_signature = CredentialSignature {
            p_credential: p_cred,
            r_credential: Some(r_cred),
        };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(
            &credential_pub_key.p_key,
            &credential_priv_key.p_key,
            &cred_signature.p_credential,
            &q,
            credential_issuance_nonce,
        )?;

        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}, rev_reg_delta: {:?}",
               secret!(&cred_signature), signature_correctness_proof, rev_reg_delta);

        Ok((cred_signature, signature_correctness_proof, rev_reg_delta))
    }

    /// Revokes a credential by a rev_idx in a given revocation registry.
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    /// * `rev_idx` - Index of the user in the revocation registry.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::{new_nonce, SimpleTailsAccessor};
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// ```
    pub fn revoke_credential<RTA>(
        rev_reg: &mut RevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        rev_tails_accessor: &RTA,
    ) -> UrsaCryptoResult<RevocationRegistryDelta>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "Issuer::revoke_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(rev_idx)
        );

        let prev_accum = rev_reg.accum;

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.sub(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum,
            issued: HashSet::new(),
            revoked: hashset![rev_idx],
        };

        trace!(
            "Issuer::revoke_credential: <<< rev_reg_delta: {:?}",
            rev_reg_delta
        );

        Ok(rev_reg_delta)
    }

    /// Recovery a credential by a rev_idx in a given revocation registry
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    /// * `rev_idx` - Index of the user in the revocation registry.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use ursa::cl::{new_nonce, SimpleTailsAccessor};
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    ///
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// Issuer::revoke_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// Issuer::recovery_credential(&mut rev_reg, max_cred_num, rev_idx, &simple_tail_accessor).unwrap();
    /// ```
    pub fn recovery_credential<RTA>(
        rev_reg: &mut RevocationRegistry,
        max_cred_num: u32,
        rev_idx: u32,
        rev_tails_accessor: &RTA,
    ) -> UrsaCryptoResult<RevocationRegistryDelta>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "Issuer::recovery_credential: >>> rev_reg: {:?}, max_cred_num: {:?}, rev_idx: {:?}",
            rev_reg,
            max_cred_num,
            secret!(rev_idx)
        );

        let prev_accum = rev_reg.accum;

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        rev_tails_accessor.access_tail(index, &mut |tail| {
            rev_reg.accum = rev_reg.accum.add(tail).unwrap();
        })?;

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_accum),
            accum: rev_reg.accum,
            issued: hashset![rev_idx],
            revoked: HashSet::new(),
        };

        trace!(
            "Issuer::recovery_credential: <<< rev_reg_delta: {:?}",
            rev_reg_delta
        );

        Ok(rev_reg_delta)
    }

    /// Updates a revocation registry with sets of issued and revoked credential indexes.
    ///
    /// # Arguments
    /// * `rev_reg` - Revocation registry.
    /// * `max_cred_num` - Max credential number in revocation registry.
    /// * `issued` - Set of issued credentials (if using issuance on demand).
    /// * `revoked` - Set of revoked credentials.
    /// * `rev_tails_accessor` - Revocation registry tails accessor.
    ///
    /// # Example
    /// ```
    /// use std::collections::BTreeSet;
    /// use ursa::cl::{new_nonce, SimpleTailsAccessor};
    /// use ursa::cl::issuer::Issuer;
    /// use ursa::cl::prover::Prover;
    ///
    /// let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
    /// credential_schema_builder.add_attr("name").unwrap();
    /// let credential_schema = credential_schema_builder.finalize().unwrap();
    ///
    /// let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    /// non_credential_schema_builder.add_attr("master_secret").unwrap();
    /// let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    ///
    /// let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();
    ///
    /// let max_cred_num = 5;
    /// let (_rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) = Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, false).unwrap();
    ///
    /// let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
    ///
    /// let master_secret = Prover::new_master_secret().unwrap();
    ///
    /// let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
    /// credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap());
    /// credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
    /// let cred_values = credential_values_builder.finalize().unwrap();
    ///
    /// let credential_nonce = new_nonce().unwrap();
    ///
    /// let (blinded_credential_secrets, _credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
    ///     Prover::blind_credential_secrets(&cred_pub_key, &cred_key_correctness_proof, &cred_values, &credential_nonce).unwrap();
    /// let credential_issuance_nonce = new_nonce().unwrap();
    ///
    /// let rev_idx = 1;
    /// let (_cred_signature, _signature_correctness_proof, _rev_reg_delta) =
    ///     Issuer::sign_credential_with_revoc("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
    ///                                        &blinded_credential_secrets,
    ///                                        &blinded_credential_secrets_correctness_proof,
    ///                                        &credential_nonce,
    ///                                        &credential_issuance_nonce,
    ///                                        &cred_values,
    ///                                        &cred_pub_key,
    ///                                        &cred_priv_key,
    ///                                        rev_idx,
    ///                                        max_cred_num,
    ///                                        false,
    ///                                        &mut rev_reg,
    ///                                        &rev_key_priv,
    ///                                         &simple_tail_accessor).unwrap();
    /// let mut issued = BTreeSet::new();
    /// issued.insert(rev_idx);
    /// let revoked = BTreeSet::new();
    /// Issuer::update_revocation_registry(&mut rev_reg, max_cred_num, issued, revoked, &simple_tail_accessor).unwrap();
    /// ```
    pub fn update_revocation_registry<RTA>(
        rev_reg: &mut RevocationRegistry,
        max_cred_num: u32,
        issued: BTreeSet<u32>,
        revoked: BTreeSet<u32>,
        rev_tails_accessor: &RTA,
    ) -> UrsaCryptoResult<RevocationRegistryDelta>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "Issuer::update_revocation_registry: >>> rev_reg: {:?}, max_cred_num: {:?}, issued: {:?}, revoked: {:?}",
            rev_reg,
            max_cred_num,
            secret!(&issued),
            secret!(&revoked)
        );

        let prev_acc = rev_reg.accum;
        for rev_idx in issued.iter() {
            let tail_id = Self::_get_index(max_cred_num, *rev_idx);
            rev_tails_accessor.access_tail(tail_id, &mut |tail| {
                rev_reg.accum = rev_reg.accum.add(tail).unwrap()
            })?;
        }
        for rev_idx in revoked.iter() {
            let tail_id = Self::_get_index(max_cred_num, *rev_idx);
            rev_tails_accessor.access_tail(tail_id, &mut |tail| {
                rev_reg.accum = rev_reg.accum.sub(tail).unwrap()
            })?;
        }

        let rev_reg_delta = RevocationRegistryDelta {
            prev_accum: Some(prev_acc),
            accum: rev_reg.accum,
            issued: HashSet::from_iter(issued),
            revoked: HashSet::from_iter(revoked),
        };

        trace!(
            "Issuer::update_revocation_registry: <<< rev_reg_delta: {:?}",
            rev_reg_delta
        );

        Ok(rev_reg_delta)
    }

    fn _new_credential_primary_keys(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
    ) -> UrsaCryptoResult<(
        CredentialPrimaryPublicKey,
        CredentialPrimaryPrivateKey,
        CredentialPrimaryPublicKeyMetadata,
    )> {
        trace!(
            "Issuer::_new_credential_primary_keys_with_primes: >>> credential_schema: {:?}",
            credential_schema
        );

        let p_safe = generate_safe_prime(LARGE_PRIME)?;
        let q_safe = generate_safe_prime(LARGE_PRIME)?;

        Issuer::_new_credential_primary_keys_with_primes(
            credential_schema,
            non_credential_schema,
            &p_safe,
            &q_safe,
        )
    }

    fn _new_credential_primary_keys_with_primes(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        p_safe: &BigNumber,
        q_safe: &BigNumber,
    ) -> UrsaCryptoResult<(
        CredentialPrimaryPublicKey,
        CredentialPrimaryPrivateKey,
        CredentialPrimaryPublicKeyMetadata,
    )> {
        trace!(
            "Issuer::_new_credential_primary_keys_with_primes: >>> credential_schema: {:?}",
            credential_schema
        );

        let mut ctx = BigNumber::new_context()?;

        if credential_schema.attrs.is_empty() {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "List of attributes is empty",
            ));
        }

        let p = p_safe.rshift1()?;
        let q = q_safe.rshift1()?;

        let n = p_safe.mul(&q_safe, Some(&mut ctx))?;
        let s = random_qr(&n)?;
        let xz = gen_x(&p, &q)?;

        let mut xr = HashMap::new();
        for non_schema_element in &non_credential_schema.attrs {
            xr.insert(non_schema_element.to_string(), gen_x(&p, &q)?);
        }

        for attribute in &credential_schema.attrs {
            xr.insert(attribute.to_string(), gen_x(&p, &q)?);
        }

        let mut r = HashMap::new();
        for (key, xr_value) in xr.iter() {
            r.insert(key.to_string(), s.mod_exp(&xr_value, &n, Some(&mut ctx))?);
        }

        let z = s.mod_exp(&xz, &n, Some(&mut ctx))?;

        let rctxt = s.mod_exp(&gen_x(&p, &q)?, &n, Some(&mut ctx))?;

        let cred_pr_pub_key = CredentialPrimaryPublicKey { n, s, rctxt, r, z };
        let cred_pr_priv_key = CredentialPrimaryPrivateKey { p, q };
        let cred_pr_pub_key_metadata = CredentialPrimaryPublicKeyMetadata { xz, xr };

        trace!("Issuer::_new_credential_primary_keys: <<< cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_metadata: {:?}",
               cred_pr_pub_key, secret!(&cred_pr_priv_key), cred_pr_pub_key_metadata);

        Ok((cred_pr_pub_key, cred_pr_priv_key, cred_pr_pub_key_metadata))
    }

    fn _new_credential_revocation_keys() -> UrsaCryptoResult<(
        CredentialRevocationPublicKey,
        CredentialRevocationPrivateKey,
    )> {
        trace!("Issuer::_new_credential_revocation_keys: >>>");

        let h = PointG1::new()?;
        let h0 = PointG1::new()?;
        let h1 = PointG1::new()?;
        let h2 = PointG1::new()?;
        let htilde = PointG1::new()?;
        let g = PointG1::new()?;

        let u = PointG2::new()?;
        let h_cap = PointG2::new()?;

        let x = GroupOrderElement::new()?;
        let sk = GroupOrderElement::new()?;
        let g_dash = PointG2::new()?;

        let pk = g.mul(&sk)?;
        let y = h_cap.mul(&x)?;

        let cred_rev_pub_key = CredentialRevocationPublicKey {
            g,
            g_dash,
            h,
            h0,
            h1,
            h2,
            htilde,
            h_cap,
            u,
            pk,
            y,
        };
        let cred_rev_priv_key = CredentialRevocationPrivateKey { x, sk };

        trace!("Issuer::_new_credential_revocation_keys: <<< cred_rev_pub_key: {:?}, cred_rev_priv_key: {:?}", cred_rev_pub_key, secret!(&cred_rev_priv_key));

        Ok((cred_rev_pub_key, cred_rev_priv_key))
    }

    fn _new_credential_key_correctness_proof(
        cred_pr_pub_key: &CredentialPrimaryPublicKey,
        cred_pr_priv_key: &CredentialPrimaryPrivateKey,
        cred_pr_pub_key_meta: &CredentialPrimaryPublicKeyMetadata,
    ) -> UrsaCryptoResult<CredentialKeyCorrectnessProof> {
        trace!("Issuer::_new_credential_key_correctness_proof: >>> cred_pr_pub_key: {:?}, cred_pr_priv_key: {:?}, cred_pr_pub_key_meta: {:?}",
               cred_pr_pub_key, secret!(cred_pr_priv_key), cred_pr_pub_key_meta);

        let mut ctx = BigNumber::new_context()?;

        let xz_tilda = gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?;

        let mut xr_tilda = HashMap::new();
        for key in cred_pr_pub_key.r.keys() {
            xr_tilda.insert(
                key.to_string(),
                gen_x(&cred_pr_priv_key.p, &cred_pr_priv_key.q)?,
            );
        }

        let z_tilda = cred_pr_pub_key
            .s
            .mod_exp(&xz_tilda, &cred_pr_pub_key.n, Some(&mut ctx))?;

        let mut r_tilda = HashMap::new();
        for (key, xr_tilda_value) in xr_tilda.iter() {
            r_tilda.insert(
                key.to_string(),
                cred_pr_pub_key
                    .s
                    .mod_exp(&xr_tilda_value, &cred_pr_pub_key.n, Some(&mut ctx))?,
            );
        }

        let mut values: Vec<u8> = Vec::new();
        let mut ordered_attrs: Vec<String> = Vec::new();
        values.extend_from_slice(&cred_pr_pub_key.z.to_bytes()?);
        for (key, val) in cred_pr_pub_key.r.iter() {
            values.extend_from_slice(&val.to_bytes()?);
            ordered_attrs.push(key.to_owned());
        }
        values.extend_from_slice(&z_tilda.to_bytes()?);
        for attr in &ordered_attrs {
            let val = &r_tilda[attr];
            values.extend_from_slice(&val.to_bytes()?);
        }

        let c = get_hash_as_int(&[values])?;

        let xz_cap = c
            .mul(&cred_pr_pub_key_meta.xz, Some(&mut ctx))?
            .add(&xz_tilda)?;

        let mut xr_cap: Vec<(String, BigNumber)> = Vec::new();
        for key in ordered_attrs {
            let xr_tilda_value = &xr_tilda[&key];
            let val = c
                .mul(&cred_pr_pub_key_meta.xr[&key], Some(&mut ctx))?
                .add(&xr_tilda_value)?;
            xr_cap.push((key, val));
        }

        let key_correctness_proof = CredentialKeyCorrectnessProof { c, xz_cap, xr_cap };

        trace!(
            "Issuer::_new_credential_key_correctness_proof: <<< key_correctness_proof: {:?}",
            key_correctness_proof
        );

        Ok(key_correctness_proof)
    }

    fn _new_revocation_registry(
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        rev_key_priv: &RevocationKeyPrivate,
        max_cred_num: u32,
        issuance_by_default: bool,
    ) -> UrsaCryptoResult<RevocationRegistry> {
        trace!("Issuer::_new_revocation_registry: >>> cred_rev_pub_key: {:?}, rev_key_priv: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               cred_rev_pub_key, secret!(rev_key_priv), max_cred_num, issuance_by_default);

        let mut accum = Accumulator::new_inf()?;

        if issuance_by_default {
            for i in 1..=max_cred_num {
                let index = Issuer::_get_index(max_cred_num, i);
                accum = accum.add(&Tail::new_tail(
                    index,
                    &cred_rev_pub_key.g_dash,
                    &rev_key_priv.gamma,
                )?)?;
            }
        };

        let rev_reg = RevocationRegistry { accum };

        trace!(
            "Issuer::_new_revocation_registry: <<< rev_reg: {:?}",
            rev_reg
        );

        Ok(rev_reg)
    }

    fn _new_revocation_registry_keys(
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        max_cred_num: u32,
    ) -> UrsaCryptoResult<(RevocationKeyPublic, RevocationKeyPrivate)> {
        trace!(
            "Issuer::_new_revocation_registry_keys: >>> cred_rev_pub_key: {:?}, max_cred_num: {:?}",
            cred_rev_pub_key,
            max_cred_num
        );

        let gamma = GroupOrderElement::new()?;

        let mut z = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;
        let mut pow =
            GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(max_cred_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;

        let rev_key_pub = RevocationKeyPublic { z };
        let rev_key_priv = RevocationKeyPrivate { gamma };

        trace!(
            "Issuer::_new_revocation_registry_keys: <<< rev_key_pub: {:?}, rev_key_priv: {:?}",
            rev_key_pub,
            secret!(&rev_key_priv)
        );

        Ok((rev_key_pub, rev_key_priv))
    }

    fn _check_blinded_credential_secrets_correctness_proof(
        blinded_cred_secrets: &BlindedCredentialSecrets,
        blinded_cred_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        nonce: &Nonce,
        cred_pr_pub_key: &CredentialPrimaryPublicKey,
    ) -> UrsaCryptoResult<()> {
        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: >>> blinded_cred_secrets: {:?}, blinded_cred_secrets_correctness_proof: {:?},\
         nonce: {:?}, cred_pr_pub_key: {:?}", blinded_cred_secrets, blinded_cred_secrets_correctness_proof, nonce, cred_pr_pub_key);

        let mut values: Vec<u8> = Vec::new();
        let mut ctx = BigNumber::new_context()?;

        let u_cap = blinded_cred_secrets.hidden_attributes.iter().fold(
            blinded_cred_secrets
                .u
                .inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_exp(
                    &blinded_cred_secrets_correctness_proof.c,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx),
                )?
                .mod_mul(
                    &cred_pr_pub_key.s.mod_exp(
                        &blinded_cred_secrets_correctness_proof.v_dash_cap,
                        &cred_pr_pub_key.n,
                        Some(&mut ctx),
                    )?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx),
                ),
            |acc, attr| {
                let pk_r = cred_pr_pub_key.r.get(&attr.clone()).ok_or_else(|| {
                    err_msg(
                        UrsaCryptoErrorKind::InvalidStructure,
                        format!("Value by key '{}' not found in cred_pr_pub_key.r", attr),
                    )
                })?;
                let m_cap = &blinded_cred_secrets_correctness_proof.m_caps[attr];
                acc?.mod_mul(
                    &pk_r.mod_exp(&m_cap, &cred_pr_pub_key.n, Some(&mut ctx))?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx),
                )
            },
        )?;

        for (key, value) in &blinded_cred_secrets.committed_attributes {
            let m_cap = &blinded_cred_secrets_correctness_proof.m_caps[key];
            let comm_att_cap = value
                .inverse(&cred_pr_pub_key.n, Some(&mut ctx))?
                .mod_exp(
                    &blinded_cred_secrets_correctness_proof.c,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx),
                )?
                .mod_mul(
                    &get_pedersen_commitment(
                        &cred_pr_pub_key.z,
                        &m_cap,
                        &cred_pr_pub_key.s,
                        &blinded_cred_secrets_correctness_proof.r_caps[key],
                        &cred_pr_pub_key.n,
                        &mut ctx,
                    )?,
                    &cred_pr_pub_key.n,
                    Some(&mut ctx),
                )?;

            values.extend_from_slice(&comm_att_cap.to_bytes()?);
            values.extend_from_slice(&value.to_bytes()?);
        }

        values.extend_from_slice(&blinded_cred_secrets.u.to_bytes()?);
        values.extend_from_slice(&u_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&[values])?;

        let valid = blinded_cred_secrets_correctness_proof.c.eq(&c);

        if !valid {
            return Err(err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "Invalid BlindedCredentialSecrets correctness proof",
            ));
        }

        trace!("Issuer::_check_blinded_credential_secrets_correctness_proof: <<<");

        Ok(())
    }

    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    fn _gen_credential_context(
        prover_id: &str,
        rev_idx: Option<u32>,
    ) -> UrsaCryptoResult<BigNumber> {
        trace!(
            "Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}",
            prover_id,
            secret!(rev_idx)
        );

        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);

        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&prover_id_bn.to_bytes()?);
        values.extend_from_slice(&rev_idx_bn.to_bytes()?);

        let credential_context = get_hash_as_int(&[values])?;

        trace!(
            "Issuer::_gen_credential_context: <<< credential_context: {:?}",
            secret!(&credential_context)
        );

        Ok(credential_context)
    }

    fn _new_credential_def_with_keys(
        credential_schema: &CredentialSchema,
        support_revocation: bool,
        p_pub_key: CredentialPrimaryPublicKey,
        p_priv_key: CredentialPrimaryPrivateKey,
        p_key_meta: CredentialPrimaryPublicKeyMetadata,
    ) -> UrsaCryptoResult<(
        CredentialPublicKey,
        CredentialPrivateKey,
        CredentialKeyCorrectnessProof,
    )> {
        trace!(
            "Issuer::new_credential_def_with_primes: >>> credential_schema: {:?}, support_revocation: {:?}",
            credential_schema,
            support_revocation
        );

        let (r_pub_key, r_priv_key) = if support_revocation {
            Issuer::_new_credential_revocation_keys()
                .map(|(r_pub_key, r_priv_key)| (Some(r_pub_key), Some(r_priv_key)))?
        } else {
            (None, None)
        };

        let cred_pub_key = CredentialPublicKey {
            p_key: p_pub_key,
            r_key: r_pub_key,
        };
        let cred_priv_key = CredentialPrivateKey {
            p_key: p_priv_key,
            r_key: r_priv_key,
        };
        let cred_key_correctness_proof = Issuer::_new_credential_key_correctness_proof(
            &cred_pub_key.p_key,
            &cred_priv_key.p_key,
            &p_key_meta,
        )?;

        trace!("Issuer::new_credential_def: <<< cred_pub_key: {:?}, cred_priv_key: {:?}, cred_key_correctness_proof: {:?}",
               cred_pub_key, secret!(&cred_priv_key), cred_key_correctness_proof);

        Ok((cred_pub_key, cred_priv_key, cred_key_correctness_proof))
    }

    fn _new_primary_credential(
        credential_context: &BigNumber,
        cred_pub_key: &CredentialPublicKey,
        cred_priv_key: &CredentialPrivateKey,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        cred_values: &CredentialValues,
    ) -> UrsaCryptoResult<(PrimaryCredentialSignature, BigNumber)> {
        trace!("Issuer::_new_primary_credential: >>> credential_context: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, blinded_ms: {:?},\
         cred_values: {:?}", secret!(credential_context), cred_pub_key, secret!(cred_priv_key), blinded_credential_secrets, secret!(cred_values));

        let v = generate_v_prime_prime()?;

        let e = generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE)?;
        let (a, q) = Issuer::_sign_primary_credential(
            cred_pub_key,
            cred_priv_key,
            &credential_context,
            &cred_values,
            &v,
            blinded_credential_secrets,
            &e,
        )?;

        let pr_cred_sig = PrimaryCredentialSignature {
            m_2: credential_context.try_clone()?,
            a,
            e,
            v,
        };

        trace!(
            "Issuer::_new_primary_credential: <<< pr_cred_sig: {:?}, q: {:?}",
            secret!(&pr_cred_sig),
            secret!(&q)
        );

        Ok((pr_cred_sig, q))
    }

    fn _sign_primary_credential(
        cred_pub_key: &CredentialPublicKey,
        cred_priv_key: &CredentialPrivateKey,
        cred_context: &BigNumber,
        cred_values: &CredentialValues,
        v: &BigNumber,
        blinded_cred_secrets: &BlindedCredentialSecrets,
        e: &BigNumber,
    ) -> UrsaCryptoResult<(BigNumber, BigNumber)> {
        trace!(
            "Issuer::_sign_primary_credential: >>> cred_pub_key: {:?}, \
             cred_priv_key: {:?}, \
             cred_context: {:?}, \
             cred_values: {:?}, \
             v: {:?},\
             blinded_cred_secrets: {:?}, \
             e: {:?}",
            cred_pub_key,
            secret!(cred_priv_key),
            secret!(cred_context),
            secret!(cred_values),
            secret!(v),
            blinded_cred_secrets,
            secret!(e)
        );

        let p_pub_key = &cred_pub_key.p_key;
        let p_priv_key = &cred_priv_key.p_key;

        let mut context = BigNumber::new_context()?;

        let mut rx = p_pub_key.s.mod_exp(&v, &p_pub_key.n, Some(&mut context))?;

        if blinded_cred_secrets.u != BigNumber::from_u32(0)? {
            rx = rx.mod_mul(&blinded_cred_secrets.u, &p_pub_key.n, Some(&mut context))?;
        }

        rx = rx.mod_mul(
            &p_pub_key
                .rctxt
                .mod_exp(&cred_context, &p_pub_key.n, Some(&mut context))?,
            &p_pub_key.n,
            Some(&mut context),
        )?;

        for (key, attr) in cred_values
            .attrs_values
            .iter()
            .filter(|&(_, v)| v.is_known())
        {
            let pk_r = p_pub_key.r.get(key).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in pk.r", key),
                )
            })?;

            rx = pk_r
                .mod_exp(attr.value(), &p_pub_key.n, Some(&mut context))?
                .mod_mul(&rx, &p_pub_key.n, Some(&mut context))?;
        }

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n, Some(&mut context))?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let e_inverse = e.inverse(&n, Some(&mut context))?;

        let a = q.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        trace!(
            "Issuer::_sign_primary_credential: <<< a: {:?}, q: {:?}",
            secret!(&a),
            secret!(&q)
        );

        Ok((a, q))
    }

    fn _new_signature_correctness_proof(
        p_pub_key: &CredentialPrimaryPublicKey,
        p_priv_key: &CredentialPrimaryPrivateKey,
        p_cred_signature: &PrimaryCredentialSignature,
        q: &BigNumber,
        nonce: &BigNumber,
    ) -> UrsaCryptoResult<SignatureCorrectnessProof> {
        trace!("Issuer::_new_signature_correctness_proof: >>> p_pub_key: {:?}, p_priv_key: {:?}, p_cred_signature: {:?}, q: {:?}, nonce: {:?}",
               p_pub_key, secret!(p_priv_key), secret!(p_cred_signature), secret!(q), nonce);

        let mut ctx = BigNumber::new_context()?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut ctx))?;
        let r = bn_rand_range(&n)?;

        let a_cap = q.mod_exp(&r, &p_pub_key.n, Some(&mut ctx))?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&q.to_bytes()?);
        values.extend_from_slice(&p_cred_signature.a.to_bytes()?);
        values.extend_from_slice(&a_cap.to_bytes()?);
        values.extend_from_slice(&nonce.to_bytes()?);

        let c = get_hash_as_int(&[values])?;

        let se = r.mod_sub(
            &c.mod_mul(
                &p_cred_signature.e.inverse(&n, Some(&mut ctx))?,
                &n,
                Some(&mut ctx),
            )?,
            &n,
            Some(&mut ctx),
        )?;

        let signature_correctness_proof = SignatureCorrectnessProof { c, se };

        trace!(
            "Issuer::_new_signature_correctness_proof: <<< signature_correctness_proof: {:?}",
            signature_correctness_proof
        );

        Ok(signature_correctness_proof)
    }

    fn _get_index(max_cred_num: u32, rev_idx: u32) -> u32 {
        max_cred_num + 1 - rev_idx
    }

    fn _new_non_revocation_credential(
        rev_idx: u32,
        cred_context: &BigNumber,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        cred_pub_key: &CredentialPublicKey,
        cred_priv_key: &CredentialPrivateKey,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg: &mut RevocationRegistry,
        rev_key_priv: &RevocationKeyPrivate,
        rev_tails_accessor: &dyn RevocationTailsAccessor,
    ) -> UrsaCryptoResult<(
        NonRevocationCredentialSignature,
        Option<RevocationRegistryDelta>,
    )> {
        trace!("Issuer::_new_non_revocation_credential: >>> rev_idx: {:?}, cred_context: {:?}, blinded_ms: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, \
        max_cred_num: {:?}, issuance_by_default: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               secret!(rev_idx), secret!(cred_context), blinded_credential_secrets, cred_pub_key, secret!(cred_priv_key), max_cred_num,
               issuance_by_default, rev_reg, secret!(rev_key_priv));

        let ur = blinded_credential_secrets.ur.ok_or_else(|| {
            err_msg(
                UrsaCryptoErrorKind::InvalidStructure,
                "No revocation part present in blinded master secret.",
            )
        })?;

        let r_pub_key: &CredentialRevocationPublicKey =
            cred_pub_key.r_key.as_ref().ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    "No revocation part present in credential revocation public key.er secret.",
                )
            })?;

        let r_priv_key: &CredentialRevocationPrivateKey =
            cred_priv_key.r_key.as_ref().ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    "No revocation part present in credential revocation private key.",
                )
            })?;

        let vr_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&cred_context.to_bytes()?)?;

        let g_i = {
            let i_bytes = transform_u32_to_array_of_u8(rev_idx);
            let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
            pow = rev_key_priv.gamma.pow_mod(&pow)?;
            r_pub_key.g.mul(&pow)?
        };

        let sigma = r_pub_key
            .h0
            .add(&r_pub_key.h1.mul(&m2)?)?
            .add(&ur)?
            .add(&g_i)?
            .add(&r_pub_key.h2.mul(&vr_prime_prime)?)?
            .mul(&r_priv_key.x.add_mod(&c)?.inverse()?)?;

        let sigma_i = r_pub_key.g_dash.mul(
            &r_priv_key
                .sk
                .add_mod(&rev_key_priv.gamma.pow_mod(&GroupOrderElement::from_bytes(
                    &transform_u32_to_array_of_u8(rev_idx),
                )?)?)?
                .inverse()?,
        )?;
        let u_i =
            r_pub_key
                .u
                .mul(&rev_key_priv.gamma.pow_mod(&GroupOrderElement::from_bytes(
                    &transform_u32_to_array_of_u8(rev_idx),
                )?)?)?;

        let index = Issuer::_get_index(max_cred_num, rev_idx);

        let rev_reg_delta = if issuance_by_default {
            None
        } else {
            let prev_acc = rev_reg.accum;

            rev_tails_accessor.access_tail(index, &mut |tail| {
                rev_reg.accum = rev_reg.accum.add(tail).unwrap();
            })?;

            Some(RevocationRegistryDelta {
                prev_accum: Some(prev_acc),
                accum: rev_reg.accum,
                issued: hashset![rev_idx],
                revoked: HashSet::new(),
            })
        };

        let witness_signature = WitnessSignature { sigma_i, u_i, g_i };

        let non_revocation_cred_sig = NonRevocationCredentialSignature {
            sigma,
            c,
            vr_prime_prime,
            witness_signature,
            g_i,
            i: rev_idx,
            m2,
        };

        trace!("Issuer::_new_non_revocation_credential: <<< non_revocation_cred_sig: {:?}, rev_reg_delta: {:?}",
               secret!(&non_revocation_cred_sig), rev_reg_delta);

        Ok((non_revocation_cred_sig, rev_reg_delta))
    }
}

#[cfg(test)]
mod tests {
    use self::prover::mocks as prover_mocks;
    use self::prover::Prover;
    use super::*;
    use cl::helpers::MockHelper;
    use cl::issuer::{mocks, Issuer};

    #[test]
    fn generate_context_attribute_works() {
        let rev_idx = 110;
        let user_id = "111";
        let answer = BigNumber::from_dec(
            "31894574610223295263712513093148707509913459424901632064286025736442349335521",
        )
        .unwrap();
        let result = Issuer::_gen_credential_context(user_id, Some(rev_idx)).unwrap();
        assert_eq!(result, answer);
    }

    #[test]
    fn credential_schema_builder_works() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        assert!(credential_schema.attrs.contains("sex"));
        assert!(credential_schema.attrs.contains("name"));
        assert!(credential_schema.attrs.contains("age"));
        assert!(!credential_schema.attrs.contains("height"));
    }

    #[test]
    fn credential_values_builder_works() {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_dec_known("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap();
        credential_values_builder.add_dec_known("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap();
        let credential_values = credential_values_builder.finalize().unwrap();

        assert!(credential_values.attrs_values["sex"].value().eq(&BigNumber::from_dec("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129").unwrap()));
        assert!(credential_values.attrs_values["name"].value().eq(&BigNumber::from_dec("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471").unwrap()));
        assert!(credential_values.attrs_values.get("age").is_none());
    }

    #[test]
    fn issuer_new_credential_def_works() {
        MockHelper::inject();

        let (pub_key, priv_key, mut key_correctness_proof) = Issuer::new_credential_def(
            &mocks::credential_schema(),
            &mocks::non_credential_schema(),
            true,
        )
        .unwrap();
        key_correctness_proof.xr_cap.sort();
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
        Prover::check_credential_key_correctness_proof(
            &mocks::credential_primary_public_key(),
            &mocks::credential_key_correctness_proof(),
        )
        .unwrap();
        Prover::check_credential_key_correctness_proof(&pub_key.p_key, &key_correctness_proof)
            .unwrap();
    }

    #[test]
    fn issuer_new_credential_def_with_primes_works() {
        MockHelper::inject();

        let p_safe = BigNumber::from_dec("354523743991077536080894975731562551581529686893149094297102723909349187222651576180417390984965767355243859266881031427418507634277300529382744530540561250993165409731374226909016411906383603958061650234880705686790345244242716450001775952814165876503392619880850005545420299881027970160676053165184271093843").unwrap();
        let q_safe = BigNumber::from_dec("275286699043115487852101782881471925285425232532563457037882593872089382617575828792512206695091537480973072731631999932441533079584122777128509622381066757335349592950209778579166856626597096125274011246274658744982010121160434017310112434475706961336173524810385195497780906001596548229668920176826695085339").unwrap();

        let (pub_key, priv_key, mut key_correctness_proof) =
            Issuer::new_credential_def_with_primes(
                &mocks::credential_schema(),
                &mocks::non_credential_schema(),
                true,
                &p_safe,
                &q_safe,
            )
            .unwrap();
        key_correctness_proof.xr_cap.sort();
        assert!(pub_key.r_key.is_some());
        assert!(priv_key.r_key.is_some());
        Prover::check_credential_key_correctness_proof(
            &mocks::credential_primary_public_key(),
            &mocks::credential_key_correctness_proof(),
        )
        .unwrap();
        Prover::check_credential_key_correctness_proof(&pub_key.p_key, &key_correctness_proof)
            .unwrap();
    }

    #[test]
    fn issuer_new_credential_def_works_without_revocation_part() {
        MockHelper::inject();
        let (pub_key, priv_key, mut key_correctness_proof) = Issuer::new_credential_def(
            &mocks::credential_schema(),
            &mocks::non_credential_schema(),
            false,
        )
        .unwrap();
        key_correctness_proof.xr_cap.sort();
        assert!(pub_key.r_key.is_none());
        assert!(priv_key.r_key.is_none());
        Prover::check_credential_key_correctness_proof(
            &mocks::credential_primary_public_key(),
            &mocks::credential_key_correctness_proof(),
        )
        .unwrap();
        Prover::check_credential_key_correctness_proof(&pub_key.p_key, &key_correctness_proof)
            .unwrap();
    }

    #[test]
    fn issuer_new_credential_works_for_empty_attributes() {
        let cred_attrs = CredentialSchema {
            attrs: BTreeSet::new(),
        };
        let non_cred_attrs = NonCredentialSchema {
            attrs: BTreeSet::new(),
        };
        let res = Issuer::new_credential_def(&cred_attrs, &non_cred_attrs, false);
        assert!(res.is_err())
    }

    #[test]
    fn issuer_new_revocation_registry_def_works() {
        MockHelper::inject();

        let (pub_key, _, _) = Issuer::new_credential_def(
            &mocks::credential_schema(),
            &mocks::non_credential_schema(),
            true,
        )
        .unwrap();
        Issuer::new_revocation_registry_def(&pub_key, 100, false).unwrap();
    }

    #[test]
    fn sign_primary_credential_works() {
        MockHelper::inject();

        let (pub_key, secret_key) = (
            mocks::credential_public_key(),
            mocks::credential_private_key(),
        );
        let context_attribute = mocks::m2();

        let credential_values = mocks::credential_values();
        let primary_credential = mocks::primary_credential();

        let expected_q = primary_credential
            .a
            .mod_exp(&primary_credential.e, &pub_key.p_key.n, None)
            .unwrap();

        let (credential_signature, q) = Issuer::_sign_primary_credential(
            &pub_key,
            &secret_key,
            &context_attribute,
            &credential_values,
            &primary_credential.v,
            &prover_mocks::blinded_credential_secrets(),
            &primary_credential.e,
        )
        .unwrap();
        assert_eq!(primary_credential.a, credential_signature);
        assert_eq!(expected_q, q);
    }

    #[test]
    fn sign_credential_signature_works() {
        MockHelper::inject();

        let (pub_key, priv_key) = (
            mocks::credential_public_key(),
            mocks::credential_private_key(),
        );
        let blinded_credential_secrets_nonce = mocks::credential_nonce();
        let (blinded_credential_secrets, blinded_credential_secrets_correctness_proof) = (
            prover::mocks::blinded_credential_secrets(),
            prover::mocks::blinded_credential_secrets_correctness_proof(),
        );

        let credential_issuance_nonce = mocks::credential_issuance_nonce();
        let (credential_signature, signature_correctness_proof) = Issuer::sign_credential(
            prover_mocks::PROVER_DID,
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &blinded_credential_secrets_nonce,
            &credential_issuance_nonce,
            &mocks::credential_values(),
            &pub_key,
            &priv_key,
        )
        .unwrap();
        let expected_credential_signature = PrimaryCredentialSignature {
            m_2: BigNumber::from_dec("69277050336954731912953999596899794023422356864020449587821228635678593076726").unwrap(),
            a: BigNumber::from_dec("55719771527635648642663059873751548110003729526149768023348858761822676000319120364271506409606539553745362391988089712782860839380068362174882980970881205548257443324903474770234925851710931167775881095664795219486517097171157739892044533499307580918474233127480498002931380124437871288479961391946733518111263194694163949838217942811760487772894297581985192342667648521402217438775092084212936876662889013332343946485295171338468571445265090484223332117189032952075382194564086833180320161752685274392741586927843333240045100816206184612454596135115597095225936094775557087900195330393833903341104420421910270703292").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap(),
            v: BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap(),
        };

        let expected_signature_correctness_proof = SignatureCorrectnessProof {
            se: BigNumber::from_dec("2316535684685338402719486099497140440509397138514378133900918780469333389486480136191111850166211328850132141833185838701387786377623699701658879707418243873469067338140105909353701983443961216560305099507619894326327011215343831546393461935652727353729569211077678341251559194609266655606583044286237683570733202945212568927881569396756593635310226246775751361393857771145736904040474358059868319224376073326444256671202625371892195787938290235698138706566228735474013375599813867888682764948153638492162885537864183419476303364006809656184241492423118811158508955306092796494765272630456714671171097052765655820709").unwrap(),
            c: BigNumber::from_dec("104614497723451518313474575657334201988423454698609284842270966472600991936715").unwrap(),
        };

        assert_eq!(
            expected_credential_signature,
            credential_signature.p_credential
        );
        assert_eq!(
            expected_signature_correctness_proof,
            signature_correctness_proof
        );
    }

    #[test]
    #[ignore]
    fn generate_mocks() {
        //        MockHelper::inject();

        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_builder.add_attr("master_secret").unwrap();
        let non_credential_schema = non_credential_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        println!("cred_pub_key={:#?}", cred_pub_key);
        println!("cred_priv_key={:#?}", cred_priv_key);
        println!(
            "cred_key_correctness_proof={:#?}",
            cred_key_correctness_proof
        );

        let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
        credential_values_builder
            .add_value_hidden(
                "master_secret",
                &prover_mocks::master_secret().value().unwrap(),
            )
            .unwrap();
        credential_values_builder
            .add_value_known("name", &string_to_bignumber("indy-crypto"))
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "25")
            .unwrap();
        credential_values_builder
            .add_value_known("sex", &string_to_bignumber("refused"))
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();

        let cred_values = credential_values_builder.finalize().unwrap();

        println!("credential_values={:#?}", cred_values);

        let credential_nonce = new_nonce().unwrap();

        println!("credential_nonce={:#?}", credential_nonce);

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        println!(
            "blinded_credential_secrets={:#?}",
            blinded_credential_secrets
        );
        println!(
            "credential_secrets_blinding_factors={:#?}",
            credential_secrets_blinding_factors
        );
        println!(
            "blinded_credential_secrets_correctness_proof={:#?}",
            blinded_credential_secrets_correctness_proof
        );

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default)
                .unwrap();
        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        println!("rev_key_pub={:#?}", rev_key_pub);
        println!("rev_key_priv={:#?}", rev_key_priv);
        println!("rev_reg={:#?}", rev_reg);

        let credential_issuance_nonce = new_nonce().unwrap();

        println!("credential_issuance_nonce={:#?}", credential_issuance_nonce);

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc(
                prover_mocks::PROVER_DID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
                &simple_tail_accessor,
            )
            .unwrap();

        println!("before prover cred_signature={:#?}", cred_signature);
        println!(
            "signature_correctness_proof={:#?}",
            signature_correctness_proof
        );
        println!("rev_reg_delta={:#?}", rev_reg_delta);

        let witness = Witness::new(
            rev_idx,
            max_cred_num,
            issuance_by_default,
            &rev_reg_delta.unwrap(),
            &simple_tail_accessor,
        )
        .unwrap();

        println!("witness={:#?}", witness);

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &credential_issuance_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();
        println!("after prover cred_signature={:#?}", cred_signature);
    }

    fn string_to_bignumber(s: &str) -> BigNumber {
        let hash = BigNumber::hash(s.as_bytes()).unwrap();
        BigNumber::from_bytes(&hash[..]).unwrap()
    }
}

pub mod mocks {
    use self::prover::mocks as prover_mocks;
    use super::*;

    pub fn m2() -> BigNumber {
        BigNumber::from_dec(
            "69500003785041890145270364348670634122591474903142468939711692725859480163330",
        )
        .unwrap()
    }

    pub fn credential_public_key() -> CredentialPublicKey {
        CredentialPublicKey {
            p_key: credential_primary_public_key(),
            r_key: Some(credential_revocation_public_key()),
        }
    }

    pub fn credential_nonce() -> Nonce {
        BigNumber::from_dec("400156503076115782845986").unwrap()
    }

    pub fn credential_issuance_nonce() -> Nonce {
        BigNumber::from_dec("56533754654551822200471").unwrap()
    }

    pub fn credential_private_key() -> CredentialPrivateKey {
        CredentialPrivateKey {
            p_key: credential_primary_private_key(),
            r_key: Some(credential_revocation_private_key()),
        }
    }

    pub fn credential_key_correctness_proof() -> CredentialKeyCorrectnessProof {
        CredentialKeyCorrectnessProof {
            c: BigNumber::from_dec("27717265955642642392454936822829767000602626651883676425118358668211358050535").unwrap(),
            xz_cap: BigNumber::from_dec("195183479411907840658865915718157252237599938555394187408669121242924229132604040216390134337550212483799639196124826353222953939803061169821920958455818253778030212467671594260774764331010150260306656204325735897119762790715520638514456987237041497335709304782811439581187400310034566087112679977409467931731740129174679768900999402724832840167050442285166116299344094727078803267248636201545845447452247449737711167611456752229449370365693922190523326037552189437231619118503667530217877672864715336009967086498314974492784160236397875467031883372538578437567133611850400790701531183895323002264918404700860035214642442774396620020443957931798520229921748578156172389005189158388482249519636").unwrap(),
            xr_cap: vec![
                ("master_secret".to_string(), BigNumber::from_dec("108994136026733300640378424935694745675064503896066529713139585837463421815059950098507298107246300653105997383204451606837296767784814604942340833368106757835366629461939259072058086534840174639920640847444403054824747351884307793557870628615807197597130835965610488749997528825184477589323420376522176291147028713002672496406829921761560934126449181642701524435791232857719005802629716780805908885704874983403784593762097512364685411820243225448982937539508718570130858653417478893497702134462904550495445542331335644514295413713806160318827234198270067137570459810376875605314610270934169075372132654993352881948277195879123027497031120364376272763189445156428620272564477681019614118490740").unwrap()),
                ("sex".to_string(), BigNumber::from_dec("128494421725086382375233821524115416815586197851442190392417092246480099785051174054522674957382143675737963720062305616928519648742934501661363289432964725251152855168164590269677142633896467309863116251341535636218212935400896530214258131292675985463052323914410465528933082897230975501988313561612789410955586295425259898672074625500011698883324917613186367885403600868991760209666288187071717845914977105311234889269772016268840277180935437440183879308910953708209604662700140948902172133494597178436053168796694560243365149173356104393562015159498718425442018744537931047419764114929814565539131131657928963434450945907332728752733520479793552386165851653893976758325941757673920571315401").unwrap()),
                ("height".to_string(), BigNumber::from_dec("325748045045647524548077382276847895755076674490322664132332956363045987787901163969206315872897454301662114071388144994966775245975603265305660946818623306357224076636344785815978373138995216222564932708400807619786734827754233733824335077506939368237535692682624529305593741647314520149930826112187999212085720462996433231318176163742242840822705280803567526905192073820619944296743321168230950632918599705990474668702361577448434219382921450637779526236936005339118262470606084420184560736544064417269840848196585675030589388236426022432139584570728489024352483534307978598783294742079505240218467306489892141868638148224503108337301981668280873577606044397225467443257713350802818685882283").unwrap()),
                ("name".to_string(), BigNumber::from_dec("253486579801916931487546562670781248553741695003599476865583980588124606757865737448325852053029692120780293391918493356221728459494312852793463647520238291073655866088421310368038022138242832515996042314286616967884755263322237222420713822312789653819487519503320154730553582540196911624941187123733257217108517466238816701318740990786583879510974346920221367074534940885785991592688437934112362785593096203907756999872909527671772234557591044030096506799653955626862788713368168122476105201481933138534149388851563054522725269594989033530326035099481884944901558253300174923391962581489779172086993395000813147242497227279505873907008312624439779939547026110882261520782543286131848078199470").unwrap()),
                ("age".to_string(), BigNumber::from_dec("167036904630660840715382000711577962010634488820831747593373621059125367511352671841761327712538986237526797036371499808014739961349448942974154463439554875421141108261859793168878317966267762075601283924810714392952556789475513355994685737803169674207049389812772070758284567806383221945528719784218187316323784883356762001587552357389243876466467979982411498706501602171333537128112479137187703197211374419535348541143914758157265197166710306381586574677469030116733453258986074614371112312920269393969476951802514715110996174745367997328658265576034251369533834237535463741496591687376181339739504803526537311904186350596102266665204465981828194901557854754923068248902775178894883571172658").unwrap())
            ]
        }
    }

    pub fn credential_primary_public_key() -> CredentialPrimaryPublicKey {
        CredentialPrimaryPublicKey {
            n: BigNumber::from_dec("97759243037584905475759031285687481526682980378485805322836601695523323795783360758373302068022340438144260881471947602176455586937981259677043548791999109648296174273478560788309521363636530397912766272865399697255732817577277920814618478501658470763261263481884676603447569204964645509549230753919029312443159670117311672282542159324109528558167904180157060827424974789616612447417149554967683862614965370708783670343197420009533093868075356814414825976381332287575302982548015954078851835419930170678631436954784177194966259746768016991096084694473538730294363242583864853775574178872006148305847575167695257447773").unwrap(),
            s: BigNumber::from_dec("21776376592274679371689799030079085312051574992961722927009639996987475353996443835005173107832775990869009336327238503170881191994432006015212032841637680434543156174313893820353373252035892579305653947541585359384327847475410415016431890630746420522309600510291349365515722702025418921172938767221457239170209659099845312149087785411439589602066541043235679977262703755474171462622463820016126831710692850837722575030763409518413900232724379212316686419725899086486277445051559517948685502640096519501476907831798027367886642477004142733742445333458277869264615472093824024737975750072900592045563887412129016133889").unwrap(),
            r: hashmap![
                "master_secret".to_string() => BigNumber::from_dec("23600278367881514644719111745132596572924159303153307139633714118405395795423872748236244253841972896291868344238267920572448641265269524542914037755596281712335163938428945658216123512764074907185309887337640204219305153824812035618490287116229003440283175095066796405694857291764977397276381047372374819390263373711696748797018131425783674132870776764229657206936076889526045661367508574201690948355102350559010472297465242111105422314336857402907297647065431655510793365838328472647947739742691547798197166325138761863258939799970466366588510334716568673188155525513263380006012778618903312304454922018074803231854").unwrap(),
                "sex".to_string() => BigNumber::from_dec("45905420009559506676740152645444004432612926812657234203412778546798509832343930138915645502822592997484626739565937924668836135365146235452603357524920946327729842942996858261205071441906249430830929567609951185447665489982582635834022220849454430490166326338081626809854393481789706446454118448670097773698201533116892424493609827067463688036753710752724533028826181216927715655069099001392715427558245700568323615092421503874377929485249941421537028075243874101523793585428573758998843322013892289962647546691990476845851331740934058181529683978648507397291954190962244181382070900008154042314677569973820640776324").unwrap(),
                "height".to_string() => BigNumber::from_dec("94333959363004054149954701059326281900513593795765037129430512246844371745516828451428701462299943198477105935275703530916994611221655433181288770512003503259582615024945087881420522591146407207808843169552140080927132880761627430352173324750815198666656326457453782222064276842754790048981731781729230479618597274949859131995229088916414193262192514931361113034288254109737988182443184073213712191553252100225841706342337235232978666539871324982157220788383014234038954095051659809371044131965710184206761214567960637557363959436775713672978576754096054593982093280224260907034627603504454548602427458662488538122893").unwrap(),
                "name".to_string() => BigNumber::from_dec("13746366475344903846235474634926975241638918842587208382474235803812382305623738390202472416699325318710947819471164393404046657300160431130777599949512363752279699255532766520676602087778932782551551642268680361953142547995705477252031470648760627839338781192638465660242814096792628497668532134733520862819774512844702280755228385177181826134770719398139614496818334553102303655058827333112597721389083677752174761548691146932367625405463552093310281918337645732306726411640995921029049534049899620621850218350850451959460695298206326084935111318539929976208421235801491574788159148374603817580856237304789833819817").unwrap(),
                "age".to_string() => BigNumber::from_dec("44108535381364140131192122046992150469063899682787071607923270100474406377346334974921271624609604831057319489303147005216748460433766803723946485961496483599061727462446986564337374445433414116404827930271068989186385194213881804968176421601520426938491670159716567463535602365065230923357872520681039811481068030299506899426808944428227249939916740748207937959710920879937436340264212378347807979058089055923797182684599605684112141625998891722166185124853517139266700090781771486877208441006637397349202467436687288873815866066132525168536149657142924597017827004345607609366329623658946277598385003944321738600454").unwrap()
            ],
            rctxt: BigNumber::from_dec("22367649113891905664593367589756927154620026002870686791425116899113166102463385255777947612590272326902876607965930393299017708388456014672833098517510402725906562714517383519224241769370097436360213271801024664973101516459676759121006263327545857171301256844849290876113986609209526369774492299815377779730250971480247123999361231894462657785201833140206882164481738440445907028661962175780038926095996356731476561447556285865588500666880748440388241988576483428813710093676464103155200711556185738545216528962065908814210434956734336781475483267248489836659903340870985489551641891702996597499832133432061498821350").unwrap(),
            z: BigNumber::from_dec("20971049306556516416548411855462653126934915528788169742105904685171526036021814020308366595378985697473160298612279628754632434933759095053014742445453246869014501318132129164954281672366894792411718693685773560773966579052996993259737028689495198784560422879504530423473348349585086897461177376910543665826129373202987768115430007889968052288637875214108680986123834214768628273585410552488075439001161273207000954506399869209972102566538554006252214727260705838993631349254893430895487478655362331032373744785458381443406082435300178682616238581378757588795672662888045672364001684986862571709608524646032002755410").unwrap(),
        }
    }

    pub fn credential_primary_private_key() -> CredentialPrimaryPrivateKey {
        CredentialPrimaryPrivateKey {
            p: BigNumber::from_dec("169845733102667062210342112708057488332400846991988819482622071464563407684286029364544056032399908806989143469822907614182812726893706640519192922325767574462417254709488881240958364903205880453689282784391012534277856937610157314926594763180026296287510919029189603351546563449549863794481205866523163656879").unwrap(),
            q: BigNumber::from_dec("143894169803035526868761418418687119944603466542048930131478387366967355559326115035770099001659301012917581110631485500435905126763987424191457539762604468450225523596814181681836092349922056724418114385810270608527339618291065218267346637587442046323037450461842605033682206109969445105772972591610884101473").unwrap(),
        }
    }

    pub fn credential_schema() -> CredentialSchema {
        CredentialSchema {
            attrs: btreeset![
                "name".to_string(),
                "age".to_string(),
                "height".to_string(),
                "sex".to_string()
            ],
        }
    }

    pub fn non_credential_schema() -> NonCredentialSchema {
        NonCredentialSchema {
            attrs: btreeset!["master_secret".to_string()],
        }
    }

    pub fn credential_values() -> CredentialValues {
        CredentialValues {
            attrs_values: btreemap![
                "age".to_string() => CredentialValue::Known { value: BigNumber::from_u32(25).unwrap() },
                "height".to_string() => CredentialValue::Known { value: BigNumber::from_u32(175).unwrap() },
                "master_secret".to_string() => CredentialValue::Hidden { value: prover_mocks::master_secret().value().unwrap() },
                "name".to_string() => CredentialValue::Known { value: BigNumber::from_dec("66682250590915135919393234675423675079281389286836524491448775067034910960723").unwrap() },
                "sex".to_string() => CredentialValue::Known { value: BigNumber::from_dec("59607158875075502079861259255950808097316057515161310607657216396491477298979").unwrap() }
            ],
        }
    }

    pub fn credential() -> CredentialSignature {
        CredentialSignature {
            p_credential: primary_credential(),
            r_credential: Some(revocation_credential()),
        }
    }

    pub fn primary_credential() -> PrimaryCredentialSignature {
        PrimaryCredentialSignature {
            m_2: m2(),
            a: BigNumber::from_dec("95840110198672318069386609447820151443303148951672148942302688159852522121826159131255863808996897783707552162739643131614378528599266064592118168070949684856089397179020395909339742237237109001659944052044286789806424622568162248593348615174430412805702304864926111235957265861502223089731337030295342624021263130121667019811704170784741732056631313942416364801356888740473027595965734903554651671716594105480808073860478030458113568270415524334664803892787850828500787726840657357062470014690758530620898492638223285406749451191024373781693292064727907810317973909071993122608011728847903567696437202869261275989357").unwrap(),
            e: BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929737627098149467059334482909224329289").unwrap(),
            v: BigNumber::from_dec("5177522642739961905246451779745106415833631678527419493097979847130674994322175317813358680588112397645817545181196877920447218934221099725680400456473461773006574524248907665384063283312830072032362079035632193691281908883788817802636793200613194781551766294585713214322070027475018261531627410418089083868168924860170287018794921767336755719648317286409574666350772521700691458505988025932235726856879460289646648423443424514771525778011016926307596993033343253078296271176201879297607473277600595623601315041671939318096370099538051736369903665397770132336227756463959004318265516368592033553198375866430426796045544674341661434259883646250509402187865251361939828425563368375609309858582430238374430940219571654215199985547198317474893778400630391107389154681620331195570178358047424675166497763032927210014306182717").unwrap()
        }
    }

    pub fn signature_correctness_proof() -> SignatureCorrectnessProof {
        SignatureCorrectnessProof {
            se: BigNumber::from_dec("3334734537522595512130255204133576712888755832249176083829428441939484521962804521556620094862929027472521530337737372127156982501631895923027581299032722136993626472436312493350606297392721442916460565303530477182166558150689207096881806903677798289757210986840223117805945763699774384181290561808002946169805087348964132559339873177551439262849906217425469248654905829499247516863359675175822562426801635372672443279878805810021594383745145548507699220260239027982287123656569649154121094723210761036335764581415392051068843187248254772717213818807839122116342319394224327812228224419041726224950128546006908776081").unwrap(),
            c: BigNumber::from_dec("107139004283129840615455074936926563695810744359362642795914598982169317704824").unwrap()
        }
    }

    pub fn revocation_credential() -> NonRevocationCredentialSignature {
        NonRevocationCredentialSignature {
            sigma: PointG1::from_string("1 1D18E69FA5AA97421F4AEBE933B40264261C5440090222C6AC61FEBE2CFEAA04 1 1461756FB88E41A2CB508A7057318CAFB551F4CD0C7051CBEC23DDFBC92248BC 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            c: GroupOrderElement::from_string("1AF7987A73C0CC0780C60238E136EE1709BA0DACB681C7E461250DCBD902AA4C").unwrap(),
            vr_prime_prime: GroupOrderElement::from_string("22901ECFBD8CAC21E4A041949CCAF01EDC1D555C1293FBD47D9C315785FAC643").unwrap(),
            witness_signature: witness_signature(),
            g_i: PointG1::from_string("1 15A85746D992E2E8E63447D76E63681DE743CB462817D7FA39B8A039A309E618 1 08271151A4DF81C629EE8E468968DDB4D3CD35D22342F7CEC6698A99317E892F 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            i: 1,
            m2: GroupOrderElement::from_string("099A79BA1F6D7DD6247DBE701CAE80805BED79B043B875CBB37D412BFCA6D402").unwrap(),
            }
    }

    fn witness_signature() -> WitnessSignature {
        WitnessSignature {
            sigma_i: PointG2::from_string("1 02680D6A364915CE54A5E1DA89E7F1530B9394D2756312D6D97F776B0F39CC6F 1 15DE23D8864E2703884B81CB93EC5E8EE75D59BF2A8957F1C853C7407A3AF9AC 1 06B72EAC18E9FF42298D7B9B7F220E00A944FFC1864755EBB79A70E82C370335 1 116BF610CC4368D001D9F0BE121EE8DF2C7F0BEE2F1B3FE954EAF36C13DFD06F 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                u_i: PointG2::from_string("1 076EF2B88CFA0A0F9F6C0D64E2F4BFEEC60695568C8E8157E5D540513002E157 1 03D08363B8658101B730333849E25048B145260E33A289B8933AF7BD1F488386 1 19C0C5E9F4A319CD5C8066EAE01A470A6B1689449BA919077B04A7D1682403EB 1 1A521BBD8C9E9B456163E87CA6B06B0F55C616E3494EE75A089881CB0EA6BCE9 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                g_i: PointG1::from_string("1 15A85746D992E2E8E63447D76E63681DE743CB462817D7FA39B8A039A309E618 1 08271151A4DF81C629EE8E468968DDB4D3CD35D22342F7CEC6698A99317E892F 1 0095E45DF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap()
        }
    }

    pub fn witness() -> Witness {
        Witness {
            omega: PointG2::from_string(
                "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
            )
            .unwrap(),
        }
    }

    pub fn credential_revocation_public_key() -> CredentialRevocationPublicKey {
        CredentialRevocationPublicKey {
            g: PointG1::from_string("1 03D433008A42E55FE3C6C4772D290EB3B0BF999F8281B4329E55033A32663625 1 0BDFD038889932B7C5CDD0BB846713710FBAB698201DFD4A380CDD1282E75060 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            g_dash: PointG2::from_string("1 1045C93522D11FB9EB69396032EEA008B857C7F8B3F2981C9917B1DFA8A00EC9 1 01AD44557A4240BB570FB94B33746C272CF921F33B4910B111F1CA48FCE34FC2 1 2265EAFAED9C22CD76C2FBD6FC3B88414B6B66FB4E31FCD1ED6AADE25A9D31EB 1 234B062F5159CB2E0782CFB75478E45D46EBF0F21E3CE7A2CD758687A73D5D08 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            h: PointG1::from_string("1 00779206BDAB2E3F9CC3AEFC491606554D9DB1E635EE2622CB88667175CA0389 1 0BE9C24F028E14C25D779831200252C6A3810DD441563A3ED044828A0EA1F5BF 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            h0: PointG1::from_string("1 124B7A0EC17EAAB267EAD5B14BA9817F95D6ADBD2901D358B4933C17D09C6071 1 10B385CDBD3AE37E2B15A2BABE9B6A65CAF7B0266FFBCAB39DA8E89930CFE1F5 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            h1: PointG1::from_string("1 18FAE93FC4CB59CAF8EB9089BD2E3557A846B36ABF07423D38CF1F33AF40A4DA 1 135F13A5EE3A671FBB8686F5ED75208A7B21E60B5B17E130B0CD5759EEF41979 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            h2: PointG1::from_string("1 14E2B023E16BD5EFAB21C3B4E0F8DD9EDC0BAE8C7D54E53B788D5CC56428EF89 1 2455046265245AC7B96963FAF88388B80931A3A4A1789C999700E6F285C41285 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            htilde: PointG1::from_string("1 0C5D3DF7856F0C6A46ECFE1699691DC7A6BDBCB577EB811C3D582BEE15E40F43 1 072448B835886119629FD29ED7662FAAF0A46072DE824F624F1A7B137A4377D6 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            h_cap: PointG2::from_string("1 203CCE35A8D290493AF0EF4EAA52D70709E6E9D25F8B626B21B0E98941A9942D 1 2140127125274C73B172182F03F045DE38C0075111F6521C6D8AB16715394CDD 1 187548EFF78D6B382E10B857405FC959B7E60638D868DF52690FADD253156E41 1 0C4214C598DBD81107B849F8384584685EAEAC89006077D6936AD20973A751D5 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            u: PointG2::from_string("1 052DA02C48E7D4EF773EA47DF30FEB879D28ED3EA259B657A9713D09F33637FB 1 076DB5DC50643AC85A5867CC0BBEA8D1B0C0181902F7ED9E356F2E46F37F2493 1 0B0E88CB9F09987275EC5AF187269BA763B98A7C7C4BDFE2F419546BDCD9526E 1 07E87398A50B8318C0A2C9F446C9831AEFA86C04234675F796CE9EDEBF811C03 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            pk: PointG1::from_string("1 15D5FF3E86C2F9CEB0EB8967803C652A70919D57401F1A20486875FD1EFDF65B 1 1F9D0690B0A65C3EDD7F92B60620702EA103E42782946F176296FE763422BC77 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap(),
            y: PointG2::from_string("1 0844D621856F5A86017BD7993B71FF1931DBD5F81A0BDBAF1D07341C80BF77AC 1 10DC3E0107342500869DFB5028422FE8DE23E55EE6CC8AB29D0FA90387D334B0 1 21059570192BE05E2C9B32F9A9D5A56BC213E16E4D672A122088F19A33087AFC 1 03A4B1451CCB9E3CEF547973E52FD807074DDC98FB8FE81798739DB2AE7802B4 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        }
    }

    pub fn credential_revocation_private_key() -> CredentialRevocationPrivateKey {
        CredentialRevocationPrivateKey {
            x: GroupOrderElement::from_string(
                "17F6C5FC0B644FF12D490ADF6A0A2D3CD6461E05982D2E9CA5F01DC9349F3FC3",
            )
            .unwrap(),
            sk: GroupOrderElement::from_string(
                "00EBA7895708BE6EFE994C8712AC2ECA3E01A395F5DCD70CDF43B7F58080CAB8",
            )
            .unwrap(),
        }
    }

    pub fn revocation_key_public() -> RevocationKeyPublic {
        RevocationKeyPublic {
            z: Pair::from_string("BAF4F6C1044467 B355263E5FED41 8C0AF4C3EB94AF 3DE0C83ACA9928 2D6A7C6 FDF167021A1737 F7663EE5B2767B C5C4D3E69D387 34AA472296FCC7 B1660F7 C4741C69824558 CE22B92C952568 BB8179722E1BE7 1036505FEC026E 1C07F9FD DEAB5ECFD267CE 2E372388203E8D 973CB3DFAED87A EAB1BCFACB147E 12AC5746 BA65AD126B3FA5 1E1CF9FFC748E9 6017A982889E18 7AC0602B49C5E4 BAF574F 6CF7E2221ABC1 C4ABDFD08A7CD4 5CF4AB327CE15 3135590EE8EFC4 8192962 4FFCD9C89ABC45 3E0764B6CD0CF7 228E1021AA539B 8BA7447BCE3D7F F203473 DFB3E31073CDBD 7924EAC9D036C1 716066DCE76DC9 87B72FD4831A7 7296BA1 F417B8E0DAA939 9CA99939CB747E C79AC00D77664D D5C8F4836CDC28 1C615963 FD093CEBD6DED8 D16D939D4144E6 D209EEB27A2D40 E10AC83BFD60E4 4221B1A 535859DCF661A3 4A2F9EA4995F28 F9E4ECB0F4A21F CCB9D054387AF6 1B0A327E 20BF74410EF2D0 878F7EC03EA36B 76029AEF058F80 D988F4E307EC0E B9001C").unwrap()
        }
    }

    pub fn revocation_key_private() -> RevocationKeyPrivate {
        RevocationKeyPrivate {
            gamma: GroupOrderElement::from_string(
                "9A7934671787E7 B44902FD431283 E541AB2729B4F7 E4BDDF7F08FE77 19ADFD0",
            )
            .unwrap(),
        }
    }

    fn accumulator() -> Accumulator {
        PointG2::from_string("DABF1B89B584A1 6528C2CA3BB434 797565BB1CCB90 E63C6A6DC3C91A 24471A93 31D1B4E5C6F7E8 A4C48C9D1E4D0F BF10C3FBF53B80 27C94984204EFC 17DBA383 32F293DFC739DF 7E3DD3E71A4918 E2D84BF08244AE 3D7178DB477364 22738A3 3F9BCA3702EBD8 F8039636941D3C 1CE9B219CC559 9408F318813CCD 16C4CE4 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0").unwrap()
    }

    pub fn revocation_registry() -> RevocationRegistry {
        RevocationRegistry {
            accum: accumulator(),
        }
    }

    pub fn max_cred_num() -> u32 {
        5
    }

    pub fn revocation_registry_delta() -> RevocationRegistryDelta {
        RevocationRegistryDelta {
            prev_accum: Some(
                PointG2::from_string("0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
                    .unwrap(),
            ),
            accum: accumulator(),
            issued: hashset![1],
            revoked: HashSet::new(),
        }
    }

    pub fn r_cnxt_m2() -> BigNumber {
        BigNumber::from_dec(
            "69500003785041890145270364348670634122591474903142468939711692725859480163330",
        )
        .unwrap()
    }
}

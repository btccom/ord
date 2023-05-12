use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{opcodes, script},
    policy::MAX_STANDARD_TX_WEIGHT,
    schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    util::key::PrivateKey,
    util::sighash::{Prevouts, SighashCache},
    util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    PackedLockTime, SchnorrSighashType, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};

#[derive(Serialize)]
struct Output {
  commit: Txid,
  inscription: InscriptionId,
  reveal: Txid,
  fees: u64,
  reveals: Vec<Txid>,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(
    long,
    default_value = "1.0",
    help = "Use fee rate of <FEE_RATE> sats/vB"
  )]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> sats/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe sat with contents of <FILE>")]
  pub(crate) file: PathBuf,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address>,
  #[clap(long, help = "Reveal times, default 1.")]
  pub(crate) times: u64,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let inscription = Inscription::from_file(options.chain(), &self.file)?;

    let index = Index::open(&options)?;
    index.update()?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;

    let inscriptions = index.get_inscriptions(None)?;

    let commit_tx_change = [get_change_address(&client)?, get_change_address(&client)?];

    let reveal_tx_destination = self
      .destination
      .map(Ok)
      .unwrap_or_else(|| get_change_address(&client))?;

    let (unsigned_commit_tx, seg_tx, reveal_txs, recovery_key_pair) =
      Inscribe::create_inscription_transactions(
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        reveal_tx_destination,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
        self.times,
      )?;

    utxos.insert(
      seg_tx.input[0].previous_output,
      Amount::from_sat(unsigned_commit_tx.output[0].value),
    );

    let mut fees =
      Self::calculate_fee(&unsigned_commit_tx, &utxos) + Self::calculate_fee(&seg_tx, &utxos);
    
    for (_vout, reveal_tx) in reveal_txs.iter().enumerate() {
      utxos.insert(
        reveal_tx.input[0].previous_output,
        Amount::from_sat(seg_tx.output[_vout + 1].value),
      );
      fees = fees + Self::calculate_fee(&reveal_tx, &utxos)
    }

    if self.dry_run {
      let mut reveals = Vec::new();
      for reveal_tx in reveal_txs.iter() {
        reveals.push(reveal_tx.txid());
      }
      print_json(Output {
        commit: unsigned_commit_tx.txid(),
        reveal: seg_tx.txid(),
        inscription: seg_tx.txid().into(),
        fees: fees,
        reveals: reveals,
      })?;
    } else {
      if !self.no_backup {
        Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

      let seg = client
        .send_raw_transaction(&seg_tx)
        .context("Failed to send seg transaction")?;

      let mut reveals = Vec::new();
      for reveal_tx in reveal_txs.iter() {
        let reveal = client
          .send_raw_transaction(&*reveal_tx)
          .context("Failed to send reveal transaction")?;
        reveals.push(reveal);
      }

      print_json(Output {
        commit: commit,
        reveal: seg,
        inscription: seg.into(),
        fees: fees,
        reveals: reveals,
      })?;
    };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tx.input
      .iter()
      .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat())
      .sum::<u64>()
      .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>())
      .unwrap()
  }

  fn create_inscription_transactions(
    satpoint: Option<SatPoint>,
    inscription: Inscription,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    network: Network,
    utxos: BTreeMap<OutPoint, Amount>,
    change: [Address; 2],
    destination: Address,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
    times: u64,
  ) -> Result<(Transaction, Transaction, Vec<Transaction>, TweakedKeyPair)> {
    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        return Err(anyhow!("sat at {} already inscribed", satpoint));
      }

      if inscribed_satpoint.outpoint == satpoint.outpoint {
        return Err(anyhow!(
          "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
          satpoint.outpoint,
        ));
      }
    }

    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let reveal_script = inscription.append_reveal_script(
      script::Builder::new()
        .push_slice(&public_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG),
    );

    let taproot_spend_info = TaprootBuilder::new()
      .add_leaf(0, reveal_script.clone())
      .expect("adding leaf should work")
      .finalize(&secp256k1, public_key)
      .expect("finalizing taproot builder should work");

    let control_block = taproot_spend_info
      .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
      .expect("should compute control block");

    let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    let (_, reveal_fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint::null(),
      vec![TxOut {
        script_pubkey: destination.script_pubkey(),
        value: 0,
      }],
      &reveal_script,
    );
    // 给用户转一笔同时拆分n-1笔
    let mut outputs = Vec::<TxOut>::new();
    outputs.push({
      TxOut {
        script_pubkey: destination.script_pubkey(),
        value: TransactionBuilder::TARGET_POSTAGE.to_sat(),
      }
    });
    for _ in 1..times {
      outputs.push({
        TxOut {
          script_pubkey: commit_tx_address.script_pubkey(),
          value: TransactionBuilder::TARGET_POSTAGE.to_sat() + reveal_fee.to_sat(),
        }
      });
    }
    let (_, seg_fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint::null(),
      outputs.clone(),
      &reveal_script,
    );

    let unsigned_commit_tx = TransactionBuilder::build_transaction_with_value(
      satpoint,
      inscriptions,
      utxos,
      commit_tx_address.clone(),
      change,
      commit_fee_rate,
      reveal_fee * (times - 1) + seg_fee + TransactionBuilder::TARGET_POSTAGE * times,
    )?;

    let (vout, output) = unsigned_commit_tx
      .output
      .iter()
      .enumerate()
      .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
      .expect("should find sat commit/inscription output");

    let (mut seg_tx, _) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: vout.try_into().unwrap(),
      },
      outputs,
      &reveal_script,
    );

    let mut sighash_cache = SighashCache::new(&mut seg_tx);

    let signature_hash = sighash_cache
      .taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[output]),
        TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
        SchnorrSighashType::Default,
      )
      .expect("signature hash should compute");

    let signature = secp256k1.sign_schnorr(
      &secp256k1::Message::from_slice(signature_hash.as_inner())
        .expect("should be cryptographically secure hash"),
      &key_pair,
    );

    let witness = sighash_cache
      .witness_mut(0)
      .expect("getting mutable witness reference should work");
    witness.push(signature.as_ref());
    witness.push(&reveal_script);
    witness.push(&control_block.serialize());

    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
      Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
        network,
      ),
      commit_tx_address
    );

    let reveal_weight = seg_tx.weight();

    if !no_limit && reveal_weight > MAX_STANDARD_TX_WEIGHT.try_into().unwrap() {
      bail!(
        "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
      );
    }

    let mut reveal_txs = Vec::new();

    for (_vout, output) in seg_tx.output.iter().enumerate() {
      if output.script_pubkey == commit_tx_address.script_pubkey(){
        let (mut reveal_tx, _) = Self::build_reveal_transaction(
          &control_block,
          reveal_fee_rate,
          OutPoint {
            txid: seg_tx.txid(),
            vout: _vout.try_into().unwrap(),
          },
          vec![TxOut {
            script_pubkey: destination.script_pubkey(),
            value: TransactionBuilder::TARGET_POSTAGE.to_sat(),
          }],
          &reveal_script,
        );
        // 签名
        let mut sighash_cache = SighashCache::new(&mut reveal_tx);

        let signature_hash = sighash_cache
          .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[output]),
            TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
            SchnorrSighashType::Default,
          )
          .expect("signature hash should compute");

        let signature = secp256k1.sign_schnorr(
          &secp256k1::Message::from_slice(signature_hash.as_inner())
            .expect("should be cryptographically secure hash"),
          &key_pair,
        );

        let witness = sighash_cache
          .witness_mut(0)
          .expect("getting mutable witness reference should work");
        witness.push(signature.as_ref());
        witness.push(&reveal_script);
        witness.push(&control_block.serialize());
        reveal_txs.push(reveal_tx);
      }
    }

    Ok((unsigned_commit_tx, seg_tx, reveal_txs, recovery_key_pair))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let recovery_private_key = PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network);

    let info = client.get_descriptor_info(&format!("rawtr({})", recovery_private_key.to_wif()))?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor: format!("rawtr({})#{}", recovery_private_key.to_wif(), info.checksum),
      timestamp: Timestamp::Now,
      active: Some(false),
      range: None,
      next_index: None,
      internal: Some(false),
      label: Some("commit tx recovery key".to_string()),
    })?;

    for result in response {
      if !result.success {
        return Err(anyhow!("commit tx recovery key import failed"));
      }
    }

    Ok(())
  }

  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: Vec<TxOut>,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: output,
      lock_time: PackedLockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, fee)
  }
}

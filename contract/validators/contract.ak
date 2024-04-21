use aiken/transaction.{Input, ScriptContext, Spend, Transaction}
use aiken/transaction/credential.{Address}
use aiken/transaction/value.{Value}
use assist/count
use assist/find
use assist/payout
use assist/signing
use assist/types/cip68.{CIP68}
use assist/types/hashes.{PublicKeyHash}
use contract/types.{MetadataRedeemer, Remove, Update}

validator(public_key_hash: PublicKeyHash) {
  fn contract(
    _datum: CIP68,
    redeemer: MetadataRedeemer,
    context: ScriptContext,
  ) -> Bool {
    let ScriptContext { transaction, purpose } = context
    let Transaction { outputs, inputs, .. } = transaction
    when purpose is {
      Spend(output_reference) -> {
        let tx: Transaction = transaction
        let input: Input = find.input_by_ref(inputs, output_reference)
        let address: Address = input.output.address
        when redeemer is {
          Remove -> and {
              signing.verify_sig(tx.extra_signatories, public_key_hash)?,
              count.inputs_by_addr(inputs, address, 1)?,
              count.outputs_by_addr(outputs, address, 0)?,
            }
          Update { lovelace } -> {
            let value: Value =
              value.add(
                input.output.value,
                value.ada_policy_id,
                value.ada_asset_name,
                lovelace,
              )
            expect _: CIP68 = find.output_datum_by_addr(outputs, address)
            and {
              payout.exact(address, value, outputs)?,
              signing.verify_sig(tx.extra_signatories, public_key_hash)?,
              count.inputs_by_addr(inputs, address, 1)?,
              count.outputs_by_addr(outputs, address, 1)?,
            }
          }
        }
      }
      _ -> False
    }
  }
}

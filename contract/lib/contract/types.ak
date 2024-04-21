pub type MetadataRedeemer {
  Remove
  Update { lovelace: Int }
}

pub type MintRedeemer {
  Mint
  Burn
}

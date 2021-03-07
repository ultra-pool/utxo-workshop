use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
	decl_event, decl_module, decl_storage,
	dispatch::{DispatchResult, Vec},
	ensure,
};
use sp_core::{H256, H512};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::{BlakeTwo256, Hash, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_runtime::transaction_validity::{TransactionLongevity, ValidTransaction};

pub trait Trait: system::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

#[cfg_attr(feature = "std",derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Endcode, Decode, Hash, Debug)]
pub struct TransactionInput {
	pub outpoint: H256, //reference to a UTXO to be spent
	pub sigscript: H512, // proof
}

pub type Value = u128;

#[cfg_attr(feature = "std",derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Endcode, Decode, Hash, Debug)]
pub struct TransactionOutput {
	pub value: Value, // value associated with this UTXO
	pub pubkey: H256, // public key associated with this output, key of the UTXO's owner
}

#[cfg_attr(feature = "std",derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Endcode, Decode, Hash, Debug)]
pub struct Transaction {
	pub inouts: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
}

decl_storage! {
	trait Store for Module<T: Trait> as Utxo {
	UtxoStore build(|config: &GenesisConfig| {
		config.genesis_utxos
			.iter()
			.cloned()
			.map(|u| (BlakeTwo256::hash_of(&u), u) )
			.collect::<Vec<_>>()
		}): map hasher(identity) H256 => Option<TransactionOutput>;
		/// Total reward value to be redistributed among authorities.
		/// It is accumulated from transactions during block execution
		/// and then dispersed to validators on block finalization.
		pub RewardTotal get(reward_total): Value;
	}

	add_extra_genesis {
		config(genesis_utxos): Vec<TransactionOutput>;
	}
}

// External functions: callable by the end user
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		pub fn spend(_origin, transaction: Transaction) -> DispatchResult {
			// 1. TODO check that the transaction is valid

			// 2. write to storage
			let reward : Value = 0;
			Self::update_storage(&transaction, reward)?;

			// emit success event
			Self::deposit_event(Event::TransactionSuccess(transaction))

			Ok(())
		}

		fn on_finalize() {
			let auth: Vec<_> = Aura::authorities().iter().map(|x|{
				let r: &Public = x.as|_ref();
				r.0.into()
			}).collect();
			Self::disperse_reward(&auth);
		}
	}
}

decl_event! {
	pub enum Event {
		TransactionSuccess(Transaction)
	}
}

impl<T: Trait> Module<T> {

	fn update_storage(transaction: &Transaction, reward: Value) -> DispatchResult {
		let new_total = <RewardTotal>::get()
			.checked_add(reward)
			.ok_or("reward overflow")?;
		<RewardTotal>::put(new_total)

		// 1. remove input UTXO from utxostore
		for input in &transaction.inputs {
			<UtxoStore>::remove(input.outpoint)
		}
		// 2. Create the new UTXOs in utxostore
		let mut indexL u64 = 0;
		for output in &transaction.outputs {
			let hash = BlakeTwo256::hash_of( &(&transaction.encode(), index) );
			index = index.checked_added(1).ok_or("Output index overflow")?
			<UtxoStore>::insert(hash, output);
		}
		
		ok (())
	}

	fn disperse_reward(authorities: &[H256]) {
		// 1. divide the fairly
		let reward = <RewardTotal>::take();
		let share_value: Value = reward
			.checked_div(authorities.len() as Value
			.ok_or("No authorities")
			.unwrap();

		if share_value == 0 { return }

		let reminder = reward
			.checked_sub(share_value * authorities.len() as Value)
			.ok_or("Sub underflow")
			.unwrap();

		<RewardTotal>::put(reminder as Value);

		// 2. create utxo per validatore
		for authority in authorities {
			let utxo = TransactionOutput{
				value: share_value,
				pubkey: *authority,
			};

			let hash = BlakeTwo256::hash_of( &(&utxo,
						<system::Module<T>>::block_number().saturated_into::<u64>()));
				
				if !<UtxoStore>::contains_key(hash) {
					<UtxoStore::insert(hash, utxo);
					sp_runtime::print("Transaction reward sent to");
					sp_runtime::print(hash.as_fixed_bytes() as &[u8]);
				} else {
					sp_runtime::print("Transaction reward wasted due to hash collision");
				}
		}

		// 3. write the utxos to utxostore
	}



}


/// Tests for this module
#[cfg(test)]
mod tests {
	use super::*;

	use frame_support::{assert_ok, assert_err, impl_outer_origin, parameter_types, weights::Weight};
	use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};
	use sp_core::testing::{KeyStore, SR25519};
	use sp_core::traits::KeystoreExt;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	parameter_types! {
			pub const BlockHashCount: u64 = 250;
			pub const MaximumBlockWeight: Weight = 1024;
			pub const MaximumBlockLength: u32 = 2 * 1024;
			pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	}
	impl system::Trait for Test {
		type Origin = Origin;
		type Call = ();
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type Event = ();
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
		type ModuleToIndex = ();
		type AccountData = ();
		type OnNewAccount = ();
		type OnKilledAccount = ();
	}
	impl Trait for Test {
		type Event = ();
	}

	type Utxo = Module<Test>;

}

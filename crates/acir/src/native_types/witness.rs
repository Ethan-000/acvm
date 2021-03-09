#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Witness(pub u32);

impl Default for Witness {
    // Place holder value
    fn default() -> Witness {
        Witness(0)
    }
}

impl Witness {
    pub fn new(witness_index: u32) -> Witness {
        Witness(witness_index)
    }
    pub fn witness_index(&self) -> u32 {
        self.0
    }

    pub const fn can_defer_constraint(&self) -> bool {
        true
    }
}
